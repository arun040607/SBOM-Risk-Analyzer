"""
graph_builder.py
-----------------
Builds a directed dependency graph from the SBOM data using NetworkX.

Graph model:
    Nodes:
        - "app:<name>"      -> an application (node attribute type="application")
        - "lib:<name>@<ver>" -> a specific library version
                                 (node attribute type="library")
    Edges:
        - application -> library   : the app directly or transitively uses it
        - library -> library       : "depends_on" relationship (transitive chain)

Using "library@version" as the node key (instead of just the library name)
matters because the same library can appear at different versions in
different apps (e.g. lodash 4.17.19 vs 4.17.21), and those versions can
have very different risk. Keeping them as separate nodes keeps the graph
accurate.
"""

import networkx as nx
import matplotlib.pyplot as plt
import os

def save_dependency_graph(graph):
    os.makedirs("output", exist_ok=True)

    plt.figure(figsize=(14, 10))

    pos = nx.spring_layout(graph, seed=42)

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_size=2500,
        font_size=7,
        arrows=True
    )

    plt.title("SBOM Dependency Graph")
    plt.tight_layout()
    plt.savefig("output/dependency_graph.png")
    plt.close()

    print("Dependency graph saved to output/dependency_graph.png")

def _app_node(app_name):
    """Build the graph node id for an application."""
    return f"app:{app_name}"


def _lib_node(library, version):
    """Build the graph node id for a specific library version."""
    return f"lib:{library}@{version}"


def build_graph(dependencies_df):
    """
    Build a directed dependency graph from the dependencies DataFrame.

    Args:
        dependencies_df (pandas.DataFrame): output of parser.load_dependencies()

    Returns:
        networkx.DiGraph: nodes are applications and library versions,
        edges point from a consumer (app or library) to what it depends on.
    """
    graph = nx.DiGraph()

    # First pass: add every application and every library version as a node,
    # and connect the app directly to its DIRECT dependencies only.
    # Transitive libraries (direct=False) are wired in via the depends_on
    # chain in the second pass instead -- that's what makes depth /
    # transitive-detection meaningful rather than every library looking
    # "one hop" from the app.
    for _, row in dependencies_df.iterrows():
        app_node = _app_node(row["application"])
        lib_node = _lib_node(row["library"], row["version"])

        graph.add_node(app_node, type="application", name=row["application"])
        graph.add_node(
            lib_node,
            type="library",
            name=row["library"],
            version=row["version"],
            license=row["license"],
            direct=bool(row["direct"]),
            last_updated=str(row["last_updated"]),
        )

        if row["direct"]:
            graph.add_edge(app_node, lib_node, relationship="direct")

    # Second pass: add library -> library edges from the depends_on column.
    # depends_on only stores a library *name* (no version) in our SBOM,
    # so we connect to whichever version of that library the same
    # application already uses.
    for _, row in dependencies_df.iterrows():
        depends_on = row["depends_on"]
        if not depends_on:
            continue  # leaf library, nothing further down the chain

        lib_node = _lib_node(row["library"], row["version"])

        # Find the version of depends_on that belongs to the same application.
        match = dependencies_df[
            (dependencies_df["application"] == row["application"])
            & (dependencies_df["library"] == depends_on)
        ]

        if match.empty:
            # The child library isn't in our SBOM rows for this app.
            # Still record the relationship with an "unknown" version so
            # the chain isn't silently dropped.
            child_node = _lib_node(depends_on, "unknown")
            graph.add_node(child_node, type="library", name=depends_on, version="unknown")
        else:
            child_row = match.iloc[0]
            child_node = _lib_node(child_row["library"], child_row["version"])

        graph.add_edge(lib_node, child_node, relationship="depends_on")

    # Third pass (safety net): a row can be marked direct=False without any
    # other row's depends_on actually pointing to it (e.g. the SBOM tool
    # detected it deep in the tree but didn't record the exact parent).
    # Rather than leave that library disconnected from its application,
    # fall back to a direct app->library edge tagged "transitive" so it
    # still shows up in graph traversal and risk scoring.
    for _, row in dependencies_df.iterrows():
        if row["direct"]:
            continue
        app_node = _app_node(row["application"])
        lib_node = _lib_node(row["library"], row["version"])
        if not nx.has_path(graph, app_node, lib_node):
            graph.add_edge(app_node, lib_node, relationship="transitive")

    return graph


def get_transitive_dependencies(graph, node):
    """
    Get every library reachable from a given node (app or library),
    following the dependency chain as deep as it goes.

    Args:
        graph (networkx.DiGraph): graph from build_graph()
        node (str): a node id, e.g. "app:Employee Portal" or
                     "lib:spring-core@5.3.9"

    Returns:
        list[str]: node ids of all downstream libraries (not including
        the starting node itself).
    """
    if node not in graph:
        raise ValueError(f"[graph_builder] Node not found in graph: {node}")

    # nx.descendants() returns every node reachable by following edges
    # forward, which is exactly "everything this thing depends on,
    # directly or transitively".
    return sorted(nx.descendants(graph, node))


def get_dependency_depth(graph, app_name, library, version):
    """
    Get how many hops deep a library sits below an application.
    Depth 1 = direct dependency, depth 2+ = transitive.

    Returns:
        int or None: shortest path length, or None if unreachable.
    """
    app_node = _app_node(app_name)
    lib_node = _lib_node(library, version)
    try:
        return nx.shortest_path_length(graph, app_node, lib_node)
    except (nx.NodeNotFound, nx.NetworkXNoPath):
        return None


def visualize_graph_data(graph):
    """
    Prepare a plain-data (JSON-friendly) summary of the graph for
    rendering with Plotly or for showing on the dashboard.

    Returns:
        dict with:
            "nodes": list of {"id", "label", "type"}
            "edges": list of {"source", "target", "relationship"}
            "stats": basic graph statistics
    """
    # spring_layout spaces nodes out based on their connections, which
    # gives a readable "graph shape" for Plotly to draw without any
    # manual positioning.
    positions = nx.spring_layout(graph, seed=42)

    nodes = []
    for node_id, attrs in graph.nodes(data=True):
        x, y = positions[node_id]
        nodes.append({
            "id": node_id,
            "label": attrs.get("name", node_id),
            "type": attrs.get("type", "unknown"),
            "x": float(x),
            "y": float(y),
        })

    edges = []
    for source, target, attrs in graph.edges(data=True):
        edges.append({
            "source": source,
            "target": target,
            "relationship": attrs.get("relationship", "unknown"),
        })

    app_count = sum(1 for _, attrs in graph.nodes(data=True) if attrs.get("type") == "application")
    lib_count = sum(1 for _, attrs in graph.nodes(data=True) if attrs.get("type") == "library")

    stats = {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "application_count": app_count,
        "library_count": lib_count,
        "is_directed": graph.is_directed(),
        # A cycle would mean a circular dependency, worth flagging in a demo.
        "has_cycles": not nx.is_directed_acyclic_graph(graph),
    }

    return {"nodes": nodes, "edges": edges, "stats": stats}


# ---------------------------------------------------------------------
# Manual run / sample output
# ---------------------------------------------------------------------

if __name__ == "__main__":
    from parser import load_dependencies

    deps = load_dependencies("data/sbom_dependencies.csv")
    g = build_graph(deps)

    print(f"Graph built with {g.number_of_nodes()} nodes and {g.number_of_edges()} edges")

    sample_app = "app:Employee Portal"
    print(f"\nTransitive dependencies of {sample_app}:")
    for dep in get_transitive_dependencies(g, sample_app):
        print(" -", dep)

    depth = get_dependency_depth(g, "Employee Portal", "log4j", "2.14.1")
    print(f"\nDepth of log4j 2.14.1 under Employee Portal: {depth}")

    viz = visualize_graph_data(g)
    print("\nGraph stats:", viz["stats"])