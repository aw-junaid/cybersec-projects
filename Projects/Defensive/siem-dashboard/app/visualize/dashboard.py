import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd
import logging

logger = logging.getLogger(__name__)

class SIEMDashboard:
    """Interactive SIEM Dashboard using Dash"""
    
    def __init__(self, storage_handler):
        self.storage_handler = storage_handler
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
    
    def setup_layout(self):
        """Setup dashboard layout"""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1("SIEM Security Dashboard", 
                       style={'textAlign': 'center', 'color': '#2c3e50'}),
                html.Div(id="last-update", 
                        style={'textAlign': 'center', 'color': '#7f8c8d'})
            ], className='header'),
            
            # Controls
            html.Div([
                dcc.Dropdown(
                    id='time-range',
                    options=[
                        {'label': 'Last 1 hour', 'value': 1},
                        {'label': 'Last 6 hours', 'value': 6},
                        {'label': 'Last 24 hours', 'value': 24},
                        {'label': 'Last 7 days', 'value': 168}
                    ],
                    value=24,
                    style={'width': '200px'}
                ),
                dcc.Interval(
                    id='interval-component',
                    interval=30*1000,  # 30 seconds
                    n_intervals=0
                )
            ], style={'padding': '20px'}),
            
            # KPI Cards
            html.Div([
                html.Div([
                    html.H3(id='total-events', children='0'),
                    html.P('Total Events')
                ], className='kpi-card'),
                
                html.Div([
                    html.H3(id='total-alerts', children='0'),
                    html.P('Security Alerts')
                ], className='kpi-card'),
                
                html.Div([
                    html.H3(id='high-severity', children='0'),
                    html.P('High Severity')
                ], className='kpi-card'),
                
                html.Div([
                    html.H3(id='unique-ips', children='0'),
                    html.P('Unique IPs')
                ], className='kpi-card')
            ], className='kpi-row'),
            
            # Charts Row 1
            html.Div([
                # Events Over Time
                html.Div([
                    dcc.Graph(id='events-timeline')
                ], className='chart-container'),
                
                # Severity Distribution
                html.Div([
                    dcc.Graph(id='severity-chart')
                ], className='chart-container')
            ], className='chart-row'),
            
            # Charts Row 2
            html.Div([
                # Top Source IPs
                html.Div([
                    dcc.Graph(id='top-ips')
                ], className='chart-container'),
                
                # Event Types
                html.Div([
                    dcc.Graph(id='event-types')
                ], className='chart-container')
            ], className='chart-row'),
            
            # Alerts Table
            html.Div([
                html.H3("Recent Security Alerts"),
                dash_table.DataTable(
                    id='alerts-table',
                    columns=[
                        {"name": "Time", "id": "timestamp"},
                        {"name": "Rule", "id": "rule_name"},
                        {"name": "Severity", "id": "severity"},
                        {"name": "Description", "id": "description"},
                        {"name": "Source IPs", "id": "source_ips"}
                    ],
                    style_cell={'textAlign': 'left'},
                    style_header={
                        'backgroundColor': 'rgb(230, 230, 230)',
                        'fontWeight': 'bold'
                    },
                    style_data_conditional=[
                        {
                            'if': {'filter_query': '{severity} = "critical"'},
                            'backgroundColor': '#ff6b6b',
                            'color': 'white'
                        },
                        {
                            'if': {'filter_query': '{severity} = "high"'},
                            'backgroundColor': '#ffa8a8',
                            'color': 'black'
                        }
                    ]
                )
            ], style={'padding': '20px'}),
            
            # Events Table
            html.Div([
                html.H3("Recent Security Events"),
                dash_table.DataTable(
                    id='events-table',
                    columns=[
                        {"name": "Time", "id": "timestamp"},
                        {"name": "Source", "id": "source"},
                        {"name": "Type", "id": "event_type"},
                        {"name": "Severity", "id": "severity"},
                        {"name": "Source IP", "id": "source_ip"},
                        {"name": "Message", "id": "message"}
                    ],
                    page_size=10,
                    style_cell={'textAlign': 'left'},
                    style_header={
                        'backgroundColor': 'rgb(230, 230, 230)',
                        'fontWeight': 'bold'
                    }
                )
            ], style={'padding': '20px'})
        ])
    
    def setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            [Output('total-events', 'children'),
             Output('total-alerts', 'children'),
             Output('high-severity', 'children'),
             Output('unique-ips', 'children'),
             Output('last-update', 'children')],
            [Input('interval-component', 'n_intervals'),
             Input('time-range', 'value')]
        )
        def update_kpis(n, hours):
            """Update KPI cards"""
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)
                
                # Get data from storage
                events = self.storage_handler.get_events_by_time_range(start_time, end_time)
                alerts = self.storage_handler.get_alerts_by_time_range(start_time, end_time)
                
                # Calculate KPIs
                total_events = len(events)
                total_alerts = len(alerts)
                high_severity = len([e for e in events if e.get('severity') in ['high', 'critical']])
                unique_ips = len(set(e.get('source_ip') for e in events if e.get('source_ip')))
                
                last_update = f"Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                
                return (
                    f"{total_events:,}",
                    f"{total_alerts:,}",
                    f"{high_severity:,}",
                    f"{unique_ips:,}",
                    last_update
                )
            except Exception as e:
                logger.error(f"Error updating KPIs: {e}")
                return "0", "0", "0", "0", "Error"
        
        @self.app.callback(
            Output('events-timeline', 'figure'),
            [Input('interval-component', 'n_intervals'),
             Input('time-range', 'value')]
        )
        def update_timeline(n, hours):
            """Update events timeline chart"""
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)
                
                events = self.storage_handler.get_events_by_time_range(start_time, end_time)
                
                if not events:
                    return self._create_empty_chart("No events in selected time range")
                
                # Create DataFrame
                df = pd.DataFrame(events)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df['time_bucket'] = df['timestamp'].dt.floor('5min')  # 5-minute buckets
                
                timeline_data = df.groupby('time_bucket').size().reset_index(name='count')
                
                fig = px.line(
                    timeline_data,
                    x='time_bucket',
                    y='count',
                    title='Events Timeline',
                    labels={'time_bucket': 'Time', 'count': 'Events'}
                )
                
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Number of Events",
                    hovermode='x unified'
                )
                
                return fig
                
            except Exception as e:
                logger.error(f"Error updating timeline: {e}")
                return self._create_empty_chart("Error loading data")
        
        @self.app.callback(
            Output('severity-chart', 'figure'),
            [Input('interval-component', 'n_intervals'),
             Input('time-range', 'value')]
        )
        def update_severity_chart(n, hours):
            """Update severity distribution chart"""
            try:
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)
                
                events = self.storage_handler.get_events_by_time_range(start_time, end_time)
                
                if not events:
                    return self._create_empty_chart("No events in selected time range")
                
                df = pd.DataFrame(events)
                severity_counts = df['severity'].value_counts().reset_index()
                severity_counts.columns = ['severity', 'count']
                
                # Define colors for severity levels
                color_map = {
                    'critical': '#ff6b6b',
                    'high': '#ffa8a8', 
                    'medium': '#ffd8a8',
                    'low': '#d8f5a2',
                    'info': '#a5d8ff'
                }
                
                fig = px.pie(
                    severity_counts,
                    values='count',
                    names='severity',
                    title='Event Severity Distribution',
                    color='severity',
                    color_discrete_map=color_map
                )
                
                return fig
                
            except Exception as e:
                logger.error(f"Error updating severity chart: {e}")
                return self._create_empty_chart("Error loading data")
        
        # Add similar callbacks for other charts and tables...
        
    def _create_empty_chart(self, message):
        """Create an empty chart with message"""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=16)
        )
        return fig
    
    def run(self, host='0.0.0.0', port=8050, debug=False):
        """Run the dashboard"""
        self.app.run_server(host=host, port=port, debug=debug)
