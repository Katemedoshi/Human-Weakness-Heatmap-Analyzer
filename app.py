import streamlit as st
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import matplotlib.pyplot as plt
import seaborn as sns
import io

# Page configuration
st.set_page_config(
    page_title="Human Weakness Heatmap Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #FF6B6B;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #FF6B6B;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    </style>
""", unsafe_allow_html=True)

class HumanWeaknessAnalyzer:
    def __init__(self, db_name='security_behavior.db'):
        self.db_name = db_name
        self.conn = None
        
    def setup_database(self):
        """Create database and tables"""
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS employees (
                employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_code TEXT UNIQUE NOT NULL,
                department TEXT NOT NULL,
                tenure_months INTEGER,
                security_training_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS phishing_simulations (
                simulation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                day_of_week TEXT NOT NULL,
                hour_of_day INTEGER NOT NULL,
                device_type TEXT NOT NULL,
                location TEXT NOT NULL,
                clicked_link BOOLEAN NOT NULL,
                provided_credentials BOOLEAN NOT NULL,
                time_to_click_seconds INTEGER,
                FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
            );

            CREATE INDEX IF NOT EXISTS idx_employee_dept ON employees(department);
            CREATE INDEX IF NOT EXISTS idx_simulation_time ON phishing_simulations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_simulation_employee ON phishing_simulations(employee_id);
            CREATE INDEX IF NOT EXISTS idx_simulation_hour_day ON phishing_simulations(hour_of_day, day_of_week);
            CREATE INDEX IF NOT EXISTS idx_simulation_device ON phishing_simulations(device_type);
            CREATE INDEX IF NOT EXISTS idx_simulation_clicked ON phishing_simulations(clicked_link);
        ''')
        
        self.conn.commit()
        return True
    
    def generate_sample_data(self, num_employees=200, num_simulations=5000):
        """Generate realistic phishing simulation data"""
        cursor = self.conn.cursor()
        
        # Clear existing data
        cursor.execute('DELETE FROM phishing_simulations')
        cursor.execute('DELETE FROM employees')
        
        departments = ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'Operations']
        devices = ['Desktop', 'Mobile', 'Tablet']
        locations = ['Office', 'Remote', 'Coffee Shop', 'Airport']
        
        # Insert employees
        employees = []
        for i in range(1, num_employees + 1):
            dept = random.choice(departments)
            tenure = random.randint(1, 120)
            training_score = random.uniform(60, 100)
            employees.append((f"EMP{i:04d}", dept, tenure, training_score))
        
        cursor.executemany('''
            INSERT INTO employees (employee_code, department, tenure_months, security_training_score)
            VALUES (?, ?, ?, ?)
        ''', employees)
        
        # Insert phishing simulations
        start_date = datetime.now() - timedelta(days=90)
        simulations = []
        
        for i in range(num_simulations):
            emp_id = random.randint(1, num_employees)
            
            days_offset = random.randint(0, 89)
            hour = random.choices(
                range(24),
                weights=[2,1,1,1,1,3,5,8,10,12,10,15,20,12,10,18,22,15,8,5,4,3,2,2]
            )[0]
            
            timestamp = start_date + timedelta(days=days_offset, hours=hour, minutes=random.randint(0,59))
            day_of_week = timestamp.strftime('%A')
            
            device = random.choices(devices, weights=[60, 30, 10])[0]
            location = random.choice(locations)
            
            risk_score = 0.15
            if hour >= 12 and hour <= 13: risk_score += 0.10
            if hour >= 16 and hour <= 18: risk_score += 0.15
            if hour >= 22 or hour <= 6: risk_score += 0.08
            if day_of_week == 'Monday': risk_score += 0.08
            if day_of_week == 'Friday': risk_score += 0.05
            if device == 'Mobile': risk_score += 0.12
            if device == 'Tablet': risk_score += 0.08
            if location in ['Coffee Shop', 'Airport']: risk_score += 0.10
            
            clicked = random.random() < risk_score
            provided_credentials = clicked and random.random() < 0.35
            time_to_click = random.randint(5, 300) if clicked else None
            
            simulations.append((
                emp_id, timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                day_of_week, hour, device, location,
                clicked, provided_credentials, time_to_click
            ))
        
        cursor.executemany('''
            INSERT INTO phishing_simulations 
            (employee_id, timestamp, day_of_week, hour_of_day, 
             device_type, location, clicked_link, provided_credentials, time_to_click_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', simulations)
        
        self.conn.commit()
        return num_employees, num_simulations
    
    def import_employees_csv(self, uploaded_file):
        """Import employee data from uploaded CSV"""
        try:
            df = pd.read_csv(uploaded_file)
            
            required_cols = ['employee_code', 'department']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                return False, f"Missing columns: {missing_cols}"
            
            if 'tenure_months' not in df.columns:
                df['tenure_months'] = 12
            if 'security_training_score' not in df.columns:
                df['security_training_score'] = 75.0
            
            cursor = self.conn.cursor()
            for _, row in df.iterrows():
                cursor.execute('''
                    INSERT OR IGNORE INTO employees 
                    (employee_code, department, tenure_months, security_training_score)
                    VALUES (?, ?, ?, ?)
                ''', (row['employee_code'], row['department'], 
                      row['tenure_months'], row['security_training_score']))
            
            self.conn.commit()
            return True, f"Imported {len(df)} employees"
            
        except Exception as e:
            return False, str(e)
    
    def import_simulations_csv(self, uploaded_file):
        """Import phishing simulation data from uploaded CSV"""
        try:
            df = pd.read_csv(uploaded_file)
            
            required_cols = ['employee_code', 'timestamp', 'device_type', 'location', 'clicked_link']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                return False, f"Missing columns: {missing_cols}"
            
            if 'provided_credentials' not in df.columns:
                df['provided_credentials'] = False
            if 'time_to_click_seconds' not in df.columns:
                df['time_to_click_seconds'] = None
            
            cursor = self.conn.cursor()
            imported = 0
            
            for _, row in df.iterrows():
                cursor.execute('SELECT employee_id FROM employees WHERE employee_code = ?', 
                             (row['employee_code'],))
                result = cursor.fetchone()
                
                if not result:
                    continue
                
                employee_id = result[0]
                ts = pd.to_datetime(row['timestamp'])
                day_of_week = ts.strftime('%A')
                hour_of_day = ts.hour
                
                clicked = str(row['clicked_link']).lower() in ['true', '1', 'yes']
                provided_creds = str(row['provided_credentials']).lower() in ['true', '1', 'yes']
                
                cursor.execute('''
                    INSERT INTO phishing_simulations 
                    (employee_id, timestamp, day_of_week, hour_of_day, device_type, 
                     location, clicked_link, provided_credentials, time_to_click_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (employee_id, ts.strftime('%Y-%m-%d %H:%M:%S'), day_of_week, 
                      hour_of_day, row['device_type'], row['location'], 
                      clicked, provided_creds, row.get('time_to_click_seconds')))
                
                imported += 1
            
            self.conn.commit()
            return True, f"Imported {imported} simulations"
            
        except Exception as e:
            return False, str(e)
    
    def get_summary_stats(self):
        """Get summary statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) FROM employees')
        stats['total_employees'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM phishing_simulations')
        stats['total_simulations'] = cursor.fetchone()[0]
        
        if stats['total_simulations'] > 0:
            cursor.execute('''
                SELECT 
                    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1)
                FROM phishing_simulations
            ''')
            stats['click_rate'] = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT 
                    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1)
                FROM phishing_simulations
            ''')
            stats['credential_rate'] = cursor.fetchone()[0]
        else:
            stats['click_rate'] = 0
            stats['credential_rate'] = 0
        
        return stats
    
    def get_time_analysis(self):
        """Get time pattern analysis"""
        query = '''
            SELECT 
                hour_of_day,
                day_of_week,
                COUNT(*) as total_simulations,
                ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate
            FROM phishing_simulations
            GROUP BY hour_of_day, day_of_week
            HAVING total_simulations >= 3
        '''
        return pd.read_sql_query(query, self.conn)
    
    def get_device_analysis(self):
        """Get device and location analysis"""
        query = '''
            SELECT 
                device_type,
                location,
                COUNT(*) as total_simulations,
                ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate
            FROM phishing_simulations
            GROUP BY device_type, location
        '''
        return pd.read_sql_query(query, self.conn)
    
    def get_department_analysis(self):
        """Get department vulnerability analysis"""
        query = '''
            SELECT 
                e.department,
                COUNT(DISTINCT e.employee_id) as employee_count,
                COUNT(ps.simulation_id) as total_simulations,
                ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as click_rate,
                ROUND(100.0 * SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as credential_rate,
                ROUND(AVG(e.security_training_score), 1) as avg_training_score
            FROM employees e
            JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
            GROUP BY e.department
            ORDER BY click_rate DESC
        '''
        return pd.read_sql_query(query, self.conn)
    
    def get_high_risk_scenarios(self):
        """Get high risk combinations"""
        query = '''
            SELECT 
                hour_of_day,
                day_of_week,
                device_type,
                location,
                COUNT(*) as simulations,
                ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate
            FROM phishing_simulations
            GROUP BY hour_of_day, day_of_week, device_type, location
            HAVING simulations >= 2
            ORDER BY click_rate DESC
            LIMIT 10
        '''
        return pd.read_sql_query(query, self.conn)
    
    def get_employee_risks(self):
        """Get employee risk profiles"""
        query = '''
            SELECT 
                e.employee_code,
                e.department,
                e.security_training_score,
                COUNT(ps.simulation_id) as total_simulations,
                SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) as times_clicked,
                ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as personal_click_rate
            FROM employees e
            JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
            GROUP BY e.employee_id
            HAVING times_clicked >= 1
            ORDER BY personal_click_rate DESC
            LIMIT 15
        '''
        return pd.read_sql_query(query, self.conn)
    
    def close(self):
        if self.conn:
            self.conn.close()

# Initialize session state
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = HumanWeaknessAnalyzer()
    st.session_state.analyzer.setup_database()
    st.session_state.data_loaded = False

analyzer = st.session_state.analyzer

# Header
st.markdown('<h1 class="main-header">🔒 Human Weakness Heatmap Analyzer</h1>', unsafe_allow_html=True)
st.markdown("**Analyze when and why humans fail in cybersecurity - not just attack counts**")

# Sidebar
with st.sidebar:
    st.header("⚙️ Data Management")
    
    data_option = st.radio(
        "Choose data source:",
        ["Generate Sample Data", "Upload CSV Files", "Manual Entry"]
    )
    
    if data_option == "Generate Sample Data":
        st.subheader("📊 Generate Sample Data")
        num_employees = st.slider("Number of Employees", 50, 500, 200, 50)
        num_simulations = st.slider("Number of Simulations", 1000, 10000, 5000, 1000)
        
        if st.button("🎲 Generate Data", type="primary"):
            with st.spinner("Generating sample data..."):
                emp_count, sim_count = analyzer.generate_sample_data(num_employees, num_simulations)
                st.session_state.data_loaded = True
                st.success(f"✅ Generated {emp_count} employees and {sim_count} simulations")
                st.rerun()
    
    elif data_option == "Upload CSV Files":
        st.subheader("📤 Upload CSV Files")
        
        emp_file = st.file_uploader("Upload Employees CSV", type=['csv'], key='emp')
        if emp_file is not None:
            success, message = analyzer.import_employees_csv(emp_file)
            if success:
                st.success(message)
                st.session_state.data_loaded = True
            else:
                st.error(message)
        
        sim_file = st.file_uploader("Upload Simulations CSV", type=['csv'], key='sim')
        if sim_file is not None:
            success, message = analyzer.import_simulations_csv(sim_file)
            if success:
                st.success(message)
                st.session_state.data_loaded = True
            else:
                st.error(message)
        
        # Download templates
        st.markdown("---")
        st.markdown("**Need templates?**")
        
        emp_template = pd.DataFrame({
            'employee_code': ['EMP001', 'EMP002'],
            'department': ['Engineering', 'Sales'],
            'tenure_months': [24, 12],
            'security_training_score': [85.5, 72.0]
        })
        
        sim_template = pd.DataFrame({
            'employee_code': ['EMP001', 'EMP002'],
            'timestamp': ['2024-01-15 09:30:00', '2024-01-16 14:45:00'],
            'device_type': ['Desktop', 'Mobile'],
            'location': ['Office', 'Coffee Shop'],
            'clicked_link': [True, False],
            'provided_credentials': [False, False],
            'time_to_click_seconds': [45, None]
        })
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "📥 Employees",
                emp_template.to_csv(index=False),
                "employee_template.csv",
                "text/csv"
            )
        with col2:
            st.download_button(
                "📥 Simulations",
                sim_template.to_csv(index=False),
                "simulation_template.csv",
                "text/csv"
            )
    
    else:  # Manual Entry
        st.subheader("✍️ Manual Entry")
        st.info("Add data manually through the forms below")
        
        with st.expander("Add Employee"):
            emp_code = st.text_input("Employee Code", "EMP001")
            dept = st.selectbox("Department", ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'Operations'])
            tenure = st.number_input("Tenure (months)", 1, 120, 12)
            training = st.number_input("Training Score", 0.0, 100.0, 75.0)
            
            if st.button("Add Employee"):
                try:
                    cursor = analyzer.conn.cursor()
                    cursor.execute('''
                        INSERT INTO employees (employee_code, department, tenure_months, security_training_score)
                        VALUES (?, ?, ?, ?)
                    ''', (emp_code, dept, tenure, training))
                    analyzer.conn.commit()
                    st.success(f"✅ Added {emp_code}")
                    st.session_state.data_loaded = True
                except sqlite3.IntegrityError:
                    st.error("Employee already exists")

# Main content
if not st.session_state.data_loaded:
    st.info("👈 Please generate sample data or upload your CSV files to begin analysis")
    st.stop()

# Get summary stats
stats = analyzer.get_summary_stats()

if stats['total_simulations'] == 0:
    st.warning("No simulation data available. Please load data first.")
    st.stop()

# Display metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Employees", f"{stats['total_employees']:,}")

with col2:
    st.metric("Total Simulations", f"{stats['total_simulations']:,}")

with col3:
    st.metric("Click Rate", f"{stats['click_rate']:.1f}%", 
              delta=f"{stats['click_rate'] - 20:.1f}% vs baseline" if stats['click_rate'] > 0 else None,
              delta_color="inverse")

with col4:
    st.metric("Credential Rate", f"{stats['credential_rate']:.1f}%",
              delta=f"{stats['credential_rate'] - 5:.1f}% vs baseline" if stats['credential_rate'] > 0 else None,
              delta_color="inverse")

st.markdown("---")

# Tabs for different analyses
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "⏰ Time Patterns", "📱 Device & Location", "👥 Departments & Employees"])

with tab1:
    st.header("Overview Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Top Risk Scenarios")
        risk_scenarios = analyzer.get_high_risk_scenarios()
        if not risk_scenarios.empty:
            st.dataframe(risk_scenarios, use_container_width=True, hide_index=True)
        else:
            st.info("No high-risk scenarios detected")
    
    with col2:
        st.subheader("🔥 Security Recommendations")
        
        # Time-based recommendations
        time_data = analyzer.get_time_analysis()
        if not time_data.empty and time_data['click_rate'].max() > 25:
            peak = time_data.loc[time_data['click_rate'].idxmax()]
            st.warning(f"⚠️ Peak vulnerability at {int(peak['hour_of_day'])}:00 on {peak['day_of_week']}")
            st.markdown("→ Schedule additional training for high-risk time windows")
        
        # Device-based recommendations
        device_data = analyzer.get_device_analysis()
        if not device_data.empty:
            mobile = device_data[device_data['device_type'] == 'Mobile']
            if not mobile.empty and mobile['click_rate'].mean() > 20:
                st.warning(f"📱 Mobile devices show {mobile['click_rate'].mean():.1f}% click rate")
                st.markdown("→ Deploy mobile-specific security training")
        
        # Department recommendations
        dept_data = analyzer.get_department_analysis()
        if not dept_data.empty:
            vulnerable = dept_data.loc[dept_data['click_rate'].idxmax()]
            st.warning(f"🏢 {vulnerable['department']} most vulnerable ({vulnerable['click_rate']:.1f}%)")
            st.markdown("→ Prioritize targeted training for this department")

with tab2:
    st.header("⏰ Time Pattern Analysis")
    st.markdown("**Identify when users are most vulnerable to phishing attacks**")
    
    time_data = analyzer.get_time_analysis()
    
    if not time_data.empty:
        # Create heatmap
        pivot = time_data.pivot_table(index='hour_of_day', columns='day_of_week', 
                                     values='click_rate', fill_value=0)
        
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        existing_days = [day for day in day_order if day in pivot.columns]
        pivot = pivot[existing_days]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd', 
                   cbar_kws={'label': 'Click Rate (%)'}, ax=ax)
        ax.set_title('Click Rate by Hour and Day of Week', fontsize=16, fontweight='bold')
        ax.set_xlabel('Day of Week', fontsize=12)
        ax.set_ylabel('Hour of Day', fontsize=12)
        
        st.pyplot(fig)
        
        # Show data table
        with st.expander("📋 View Detailed Data"):
            st.dataframe(time_data.sort_values('click_rate', ascending=False), 
                        use_container_width=True, hide_index=True)
    else:
        st.info("Insufficient data for time pattern analysis")

with tab3:
    st.header("📱 Device & Location Analysis")
    st.markdown("**Understand how device type and location affect vulnerability**")
    
    device_data = analyzer.get_device_analysis()
    
    if not device_data.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            # Device heatmap
            pivot = device_data.pivot_table(index='device_type', columns='location', 
                                           values='click_rate', fill_value=0)
            
            fig, ax = plt.subplots(figsize=(8, 5))
            sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd',
                       cbar_kws={'label': 'Click Rate (%)'}, ax=ax)
            ax.set_title('Click Rate by Device and Location', fontsize=14, fontweight='bold')
            
            st.pyplot(fig)
        
        with col2:
            # Device comparison bar chart
            device_summary = device_data.groupby('device_type')['click_rate'].mean().reset_index()
            device_summary = device_summary.sort_values('click_rate', ascending=True)
            
            fig, ax = plt.subplots(figsize=(8, 5))
            ax.barh(device_summary['device_type'], device_summary['click_rate'], color='#FF6B6B')
            ax.set_xlabel('Average Click Rate (%)', fontsize=12)
            ax.set_title('Average Click Rate by Device Type', fontsize=14, fontweight='bold')
            ax.grid(axis='x', alpha=0.3)
            
            st.pyplot(fig)
        
        # Show data table
        with st.expander("📋 View Detailed Data"):
            st.dataframe(device_data.sort_values('click_rate', ascending=False), 
                        use_container_width=True, hide_index=True)
    else:
        st.info("Insufficient data for device analysis")

with tab4:
    st.header("👥 Department & Employee Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🏢 Department Vulnerability")
        dept_data = analyzer.get_department_analysis()
        
        if not dept_data.empty:
            fig, ax = plt.subplots(figsize=(8, 6))
            x = range(len(dept_data))
            ax.bar(x, dept_data['click_rate'], color='#FF6B6B', alpha=0.7, label='Click Rate')
            ax.bar(x, dept_data['credential_rate'], color='#EE5A6F', alpha=0.9, label='Credential Rate')
            
            ax.set_xticks(x)
            ax.set_xticklabels(dept_data['department'], rotation=45, ha='right')
            ax.set_ylabel('Rate (%)', fontsize=12)
            ax.set_title('Department Vulnerability Comparison', fontsize=14, fontweight='bold')
            ax.legend()
            ax.grid(axis='y', alpha=0.3)
            
            st.pyplot(fig)
            
            with st.expander("📋 View Department Data"):
                st.dataframe(dept_data, use_container_width=True, hide_index=True)
        else:
            st.info("No department data available")
    
    with col2:
        st.subheader("⚠️ High-Risk Employees")
        employee_risks = analyzer.get_employee_risks()
        
        if not employee_risks.empty:
            # Color code by risk level
            def color_risk(val):
                if val >= 50:
                    return 'background-color: #ffcccc'
                elif val >= 25:
                    return 'background-color: #fff4cc'
                return ''
            
            styled_df = employee_risks.style.applymap(color_risk, subset=['personal_click_rate'])
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
            
            st.caption("🔴 Red: High Risk (≥50%) | 🟡 Yellow: Medium Risk (25-49%)")
        else:
            st.info("No employee risk data available")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666; padding: 2rem;'>
        <p><strong>Human Weakness Heatmap Analyzer</strong></p>
        <p>Analyze when and why humans fail in cybersecurity contexts</p>
    </div>
    """,
    unsafe_allow_html=True
)