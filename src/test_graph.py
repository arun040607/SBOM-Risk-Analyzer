"""
test_graph.py
---------------
Simple debug script for graph_builder.py. Loads the dependency data,
builds the graph, and prints its shape so you can sanity-check the
graph construction without running the whole Flask app.

Run with:
    python src/test_graph.py
(run from the project root, so the "data/" folder is found)
"""

from parser import load_dependencies
from graph_builder import (
    build_graph,
    get_transitive_dependencies,
    visualize_graph_data,
)


def test_build_graph():
    """
    Load dependencies, build the graph, and print basic stats plus
    a preview of nodes and edges.

    Returns:
        networkx.DiGraph or None if something went wrong (so the
        other test functions below can be skipped safely).
    """
    print("\n--- Testing build_graph() ---")
    try:
        dependencies = load_dependencies("data/sbom_dependencies.csv")
        graph = build_graph(dependencies)

        print(f"Number of nodes: {graph.number_of_nodes()}")
        print(f"Number of edges: {graph.number_of_edges()}")

        print("\nFirst 10 nodes:")
        for node in list(graph.nodes)[:10]:
            print(" -", node)

        print("\nFirst 10 edges:")
        for edge in list(graph.edges)[:10]:
            print(" -", edge)

        return graph
    except Exception as e:
        print("ERROR while building graph:", e)
        return None


def test_get_transitive_dependencies(graph):
    """Pick the first application node in the graph and print what it depends on."""
    print("\n--- Testing get_transitive_dependencies() ---")
    if graph is None:
        print("Skipped: graph was not built successfully.")
        return

    try:
        # Find the first node that represents an application.
        app_nodes = [n for n, attrs in graph.nodes(data=True) if attrs.get("type") == "application"]
        if not app_nodes:
            print("No application nodes found in the graph.")
            return

        sample_app = app_nodes[0]
        deps = get_transitive_dependencies(graph, sample_app)
        print(f"Transitive dependencies of {sample_app}:")
        for dep in deps:
            print(" -", dep)
    except Exception as e:
        print("ERROR while getting transitive dependencies:", e)


def test_visualize_graph_data(graph):
    """Run visualize_graph_data() and print the summary stats it returns."""
    print("\n--- Testing visualize_graph_data() ---")
    if graph is None:
        print("Skipped: graph was not built successfully.")
        return

    try:
        viz = visualize_graph_data(graph)
        print("Graph stats:", viz["stats"])
        print(f"Nodes returned: {len(viz['nodes'])}")
        print(f"Edges returned: {len(viz['edges'])}")
    except Exception as e:
        print("ERROR while visualizing graph data:", e)


if __name__ == "__main__":
    print("Running graph_builder.py tests...")
    graph = test_build_graph()
    test_get_transitive_dependencies(graph)
    test_visualize_graph_data(graph)
    print("\nDone.")