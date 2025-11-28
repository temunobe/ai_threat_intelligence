"""
Streamlit dashboard for threat intelligence platform
"""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import pandas as pd
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pipeline import ThreatIntelligencePlatform
from graph_db import ThreatGraphDB
import config


# Page configuration
st.set_page_config(
    page_title="AI Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def initialize_platform():
    """Initialize the platform (cached)"""
    return ThreatIntelligencePlatform()


def create_network_graph(graph_data):
    """Create interactive network graph using Plotly"""
    if not graph_data['nodes']:
        return None
    
    # Create NetworkX graph
    G = nx.DiGraph()
    
    # Add nodes
    for node in graph_data['nodes']:
        G.add_node(node['id'], **node)
    
    # Add edges
    for edge in graph_data['edges']:
        G.add_edge(edge['source'], edge['target'], label=edge['label'])
    
    # Calculate layout
    pos = nx.spring_layout(G, k=2, iterations=50)
    
    # Create edge traces
    edge_trace = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_trace.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=1, color='#888'),
                hoverinfo='none',
                showlegend=False
            )
        )
    
    # Create node trace
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    
    color_map = {
        'ThreatActor': '#ff7f0e',
        'Malware': '#d62728',
        'CVE': '#9467bd',
        'IOC': '#8c564b',
        'TTP': '#e377c2'
    }
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
        node_type = G.nodes[node].get('type', 'Unknown')
        node_color.append(color_map.get(node_type, '#7f7f7f'))
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition="top center",
        marker=dict(
            size=20,
            color=node_color,
            line=dict(width=2, color='white')
        ),
        hoverinfo='text'
    )
    
    # Create figure
    fig = go.Figure(data=edge_trace + [node_trace])
    
    fig.update_layout(
        title="Threat Intelligence Graph",
        showlegend=False,
        hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='white',
        height=600
    )
    
    return fig


def main():
    """Main dashboard application"""
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ AI-Driven Threat Intelligence Platform</h1>', 
                unsafe_allow_html=True)
    st.markdown("Real-time threat analysis powered by AI and graph databases")
    
    # Initialize platform
    try:
        platform = initialize_platform()
    except Exception as e:
        st.error(f"Failed to initialize platform: {e}")
        st.info("Make sure Neo4j is running and configured correctly.")
        return
    
    # Sidebar
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["Dashboard", "Data Collection", "Threat Analysis", "Graph Explorer", "Search"]
    )
    
    # === DASHBOARD PAGE ===
    if page == "Dashboard":
        st.header("Threat Landscape Overview")
        
        # Get statistics
        landscape = platform.get_threat_landscape()
        stats = landscape['statistics']
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Threat Actors",
                stats.get('ThreatActor', 0),
                delta=None
            )
        
        with col2:
            st.metric(
                "Malware Families",
                stats.get('Malware', 0),
                delta=None
            )
        
        with col3:
            st.metric(
                "CVEs Tracked",
                stats.get('CVE', 0),
                delta=None
            )
        
        with col4:
            st.metric(
                "Total Relationships",
                stats.get('total_relationships', 0),
                delta=None
            )
        
        # Recent threats
        st.subheader("Recent Threats")
        recent = landscape['recent_threats']
        
        if recent:
            df = pd.DataFrame(recent)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No recent threats. Start by collecting data.")
        
        # Threat graph visualization
        st.subheader("Threat Network Graph")
        graph_data = landscape['graph_data']
        
        if graph_data['nodes']:
            fig = create_network_graph(graph_data)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No graph data available. Collect and process threats first.")
    
    # === DATA COLLECTION PAGE ===
    elif page == "Data Collection":
        st.header("Threat Data Collection")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            query = st.text_input("Search Query", value="ransomware", 
                                 help="Enter keywords to search for threats")
        
        with col2:
            limit = st.number_input("Limit", min_value=5, max_value=100, 
                                   value=20, step=5)
        
        sources = st.multiselect(
            "Data Sources",
            ["reddit", "blog", "twitter", "darkweb", "stix"],
            default=["reddit", "blog"],
            help="Select sources to collect from"
        )
        
        if st.button("Collect Data", type="primary"):
            with st.spinner("Collecting data..."):
                results = platform.run_pipeline(query, sources, limit)
                
                if results['status'] == 'success':
                    st.success(f"✅ Collected and processed {results['processed_items']} items")
                    
                    # Show analysis summary
                    st.subheader("Analysis Summary")
                    summary = results['analysis']['summary']
                    
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Clusters", summary['n_clusters'])
                    col2.metric("Anomalies", summary['n_anomalies'])
                    col3.metric("Critical", summary['critical_threats'])
                    col4.metric("High", summary['high_threats'])
                    
                    # Show sample results
                    st.subheader("Sample Results")
                    for i, result in enumerate(results['results'][:3]):
                        with st.expander(f"Threat {i+1} - {result['source']}"):
                            st.write(f"**Text:** {result['raw_text'][:200]}...")
                            st.write(f"**Threat Level:** {result['sentiment']['threat_level']}")
                            st.write(f"**Entities:** {result['entities']}")
                            if result['mitre_mappings']:
                                st.write(f"**MITRE Techniques:** {[m['technique_id'] for m in result['mitre_mappings'][:3]]}")
                else:
                    st.warning("No data collected")
    
    # === THREAT ANALYSIS PAGE ===
    elif page == "Threat Analysis":
        st.header("Threat Analysis")
        
        # Input threat text
        threat_text = st.text_area(
            "Enter Threat Description",
            height=150,
            placeholder="Paste threat intelligence report or IOC information..."
        )
        
        if st.button("Analyze", type="primary") and threat_text:
            with st.spinner("Analyzing threat..."):
                result = platform.process_threat_data(threat_text, "manual_input")
                
                # Show results in tabs
                tab1, tab2, tab3, tab4 = st.tabs(["Entities", "Relationships", "MITRE ATT&CK", "Sentiment"])
                
                with tab1:
                    st.subheader("Extracted Entities")
                    for entity_type, entities in result['entities'].items():
                        if entities:
                            st.write(f"**{entity_type}:** {', '.join(entities)}")
                    
                    st.subheader("IOCs")
                    for ioc_type, iocs in result['iocs'].items():
                        if iocs:
                            st.write(f"**{ioc_type.upper()}:** {', '.join(iocs)}")
                
                with tab2:
                    st.subheader("Relationships")
                    if result['relations']:
                        for rel in result['relations']:
                            st.write(f"- {rel['source']} **{rel['relation']}** {rel['target']}")
                    else:
                        st.info("No relationships extracted")
                
                with tab3:
                    st.subheader("MITRE ATT&CK Mapping")
                    if result['mitre_mappings']:
                        for mapping in result['mitre_mappings']:
                            with st.expander(f"{mapping['technique_id']}: {mapping['technique_name']}"):
                                st.write(f"**Tactics:** {', '.join(mapping['tactics'])}")
                                st.write(f"**Confidence:** {mapping['confidence']:.2%}")
                                st.write(f"**Description:** {mapping['description']}")
                    else:
                        st.info("No MITRE techniques identified")
                
                with tab4:
                    st.subheader("Threat Sentiment Analysis")
                    sentiment = result['sentiment']
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Threat Level", sentiment['threat_level'])
                        st.metric("Urgency Score", f"{sentiment['urgency_score']:.1f}/10")
                    
                    with col2:
                        if sentiment['keywords_found']:
                            st.write("**Keywords Found:**")
                            st.write(", ".join(sentiment['keywords_found']))
    
    # === GRAPH EXPLORER PAGE ===
    elif page == "Graph Explorer":
        st.header("Threat Graph Explorer")
        
        # Node search
        node_name = st.text_input("Search Node", placeholder="Enter threat actor, malware, CVE...")
        
        if node_name:
            # Get connected threats
            db = ThreatGraphDB()
            connected = db.get_connected_threats(node_name, depth=2)
            
            if connected:
                st.subheader(f"Threats Connected to '{node_name}'")
                df = pd.DataFrame(connected)
                st.dataframe(df, use_container_width=True)
            else:
                st.info(f"No node found with name '{node_name}'")
            
            db.close()
        
        # Graph statistics
        st.subheader("Graph Statistics")
        landscape = platform.get_threat_landscape()
        stats = landscape['statistics']
        
        # Create bar chart
        if stats:
            df_stats = pd.DataFrame(list(stats.items()), columns=['Type', 'Count'])
            df_stats = df_stats[df_stats['Type'] != 'total_relationships']
            
            fig = px.bar(df_stats, x='Type', y='Count', 
                        title='Node Distribution',
                        color='Type')
            st.plotly_chart(fig, use_container_width=True)
    
    # === SEARCH PAGE ===
    elif page == "Search":
        st.header("Search Threats")
        
        search_term = st.text_input("Search Term", placeholder="Enter keyword to search...")
        
        if search_term:
            results = platform.search_threats(search_term)
            
            if results:
                st.success(f"Found {len(results)} results")
                
                for result in results:
                    with st.expander(f"{result['type']}: {result['name']}"):
                        st.json(result)
            else:
                st.info("No results found")
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.info(
        "**AI-Driven Threat Intelligence Platform**\n\n"
        "CS 760 - Artificial Intelligence\n\n"
        "University of Alabama at Birmingham"
    )


if __name__ == "__main__":
    main()