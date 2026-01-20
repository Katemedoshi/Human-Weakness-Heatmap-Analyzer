import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import matplotlib.pyplot as plt
import seaborn as sns
import os

class HumanWeaknessAnalyzer:
    def __init__(self, db_name='security_behavior.db'):
        self.db_name = db_name
        self.conn = None
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
    def setup_database(self):
        """Create database and tables"""
        self.conn = sqlite3.connect(self.db_name)
        cursor = self.conn.cursor()
        
        # Check if SQL file exists, otherwise create schema directly
        schema_path = os.path.join(self.script_dir, 'schema.sql')
        
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                cursor.executescript(f.read())
            print("✓ Database schema loaded from schema.sql")
        else:
            # Create schema inline
            cursor.executescript('''
                DROP TABLE IF EXISTS phishing_simulations;
                DROP TABLE IF EXISTS employees;

                CREATE TABLE employees (
                    employee_id INTEGER PRIMARY KEY,
                    employee_code TEXT UNIQUE NOT NULL,
                    department TEXT NOT NULL,
                    tenure_months INTEGER,
                    security_training_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE phishing_simulations (
                    simulation_id INTEGER PRIMARY KEY,
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

                CREATE INDEX idx_employee_dept ON employees(department);
                CREATE INDEX idx_simulation_time ON phishing_simulations(timestamp);
                CREATE INDEX idx_simulation_employee ON phishing_simulations(employee_id);
                CREATE INDEX idx_simulation_hour_day ON phishing_simulations(hour_of_day, day_of_week);
                CREATE INDEX idx_simulation_device ON phishing_simulations(device_type);
                CREATE INDEX idx_simulation_clicked ON phishing_simulations(clicked_link);
            ''')
            print("✓ Database schema created inline")
        
        self.conn.commit()
    
    def generate_sample_data(self, num_employees=200, num_simulations=5000):
        """Generate realistic phishing simulation data"""
        cursor = self.conn.cursor()
        
        departments = ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'Operations']
        devices = ['Desktop', 'Mobile', 'Tablet']
        locations = ['Office', 'Remote', 'Coffee Shop', 'Airport']
        
        # Insert employees
        employees = []
        for i in range(1, num_employees + 1):
            dept = random.choice(departments)
            tenure = random.randint(1, 120)  # months
            training_score = random.uniform(60, 100)
            employees.append((i, f"EMP{i:04d}", dept, tenure, training_score))
        
        cursor.executemany('''
            INSERT INTO employees (employee_id, employee_code, department, tenure_months, security_training_score)
            VALUES (?, ?, ?, ?, ?)
        ''', employees)
        
        print(f"✓ Inserted {num_employees} employees")
        
        # Insert phishing simulations
        start_date = datetime.now() - timedelta(days=90)
        simulations = []
        
        for i in range(1, num_simulations + 1):
            emp_id = random.randint(1, num_employees)
            
            # Generate realistic timestamp patterns
            days_offset = random.randint(0, 89)
            hour = random.choices(
                range(24),
                weights=[2,1,1,1,1,3,5,8,10,12,10,15,20,12,10,18,22,15,8,5,4,3,2,2]
            )[0]
            
            timestamp = start_date + timedelta(days=days_offset, hours=hour, minutes=random.randint(0,59))
            day_of_week = timestamp.strftime('%A')
            
            device = random.choices(devices, weights=[60, 30, 10])[0]
            location = random.choice(locations)
            
            # Calculate click/credential probabilities based on risk factors
            risk_score = 0.15  # base rate
            
            # Time-based risks
            if hour >= 12 and hour <= 13: risk_score += 0.10  # Lunch
            if hour >= 16 and hour <= 18: risk_score += 0.15  # End of day
            if hour >= 22 or hour <= 6: risk_score += 0.08   # Off hours
            
            # Day-based risks
            if day_of_week == 'Monday': risk_score += 0.08
            if day_of_week == 'Friday': risk_score += 0.05
            
            # Device-based risks
            if device == 'Mobile': risk_score += 0.12
            if device == 'Tablet': risk_score += 0.08
            
            # Location-based risks
            if location in ['Coffee Shop', 'Airport']: risk_score += 0.10
            
            clicked = random.random() < risk_score
            provided_credentials = clicked and random.random() < 0.35
            
            time_to_click = random.randint(5, 300) if clicked else None
            
            simulations.append((
                i, emp_id, timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                day_of_week, hour, device, location,
                clicked, provided_credentials, time_to_click
            ))
        
        cursor.executemany('''
            INSERT INTO phishing_simulations 
            (simulation_id, employee_id, timestamp, day_of_week, hour_of_day, 
             device_type, location, clicked_link, provided_credentials, time_to_click_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', simulations)
        
        self.conn.commit()
        print(f"✓ Inserted {num_simulations} phishing simulations")
    
    def get_analysis_queries(self):
        """Return all analysis queries"""
        return {
            'Time Pattern Analysis': '''
                SELECT 
                    hour_of_day,
                    day_of_week,
                    COUNT(*) as total_simulations,
                    SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) as clicks,
                    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
                    SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) as credentials_provided,
                    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate
                FROM phishing_simulations
                GROUP BY hour_of_day, day_of_week
                HAVING total_simulations >= 5
                ORDER BY click_rate DESC
                LIMIT 20
            ''',
            
            'Device and Location Risk': '''
                SELECT 
                    device_type,
                    location,
                    COUNT(*) as total_simulations,
                    SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) as clicks,
                    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
                    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate
                FROM phishing_simulations
                GROUP BY device_type, location
                ORDER BY click_rate DESC
            ''',
            
            'Department Vulnerability': '''
                SELECT 
                    e.department,
                    COUNT(DISTINCT e.employee_id) as employee_count,
                    COUNT(ps.simulation_id) as total_simulations,
                    SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) as total_clicks,
                    ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as click_rate,
                    ROUND(100.0 * SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as credential_rate,
                    ROUND(AVG(e.security_training_score), 1) as avg_training_score
                FROM employees e
                JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
                GROUP BY e.department
                ORDER BY click_rate DESC
            ''',
            
            'High Risk Combinations': '''
                SELECT 
                    hour_of_day,
                    day_of_week,
                    device_type,
                    location,
                    COUNT(*) as simulations,
                    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate
                FROM phishing_simulations
                GROUP BY hour_of_day, day_of_week, device_type, location
                HAVING simulations >= 3
                ORDER BY click_rate DESC
                LIMIT 15
            ''',
            
            'Employee Risk Profile': '''
                SELECT 
                    e.employee_code,
                    e.department,
                    e.tenure_months,
                    e.security_training_score,
                    COUNT(ps.simulation_id) as total_simulations,
                    SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) as times_clicked,
                    ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as personal_click_rate,
                    SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) as times_gave_credentials
                FROM employees e
                JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
                GROUP BY e.employee_id
                HAVING times_clicked >= 2
                ORDER BY personal_click_rate DESC
                LIMIT 20
            '''
        }
    
    def run_analysis(self):
        """Execute SQL analysis queries"""
        print("\n" + "="*60)
        print("HUMAN WEAKNESS HEATMAP ANALYSIS")
        print("="*60)
        
        results = {}
        queries = self.get_analysis_queries()
        
        for query_name, query in queries.items():
            try:
                df = pd.read_sql_query(query, self.conn)
                results[query_name] = df
                
                print(f"\n{query_name}")
                print("-" * 60)
                print(df.to_string(index=False))
            except Exception as e:
                print(f"\n❌ Error in {query_name}: {str(e)}")
        
        return results
    
    def create_visualizations(self, results):
        """Generate heatmaps and visualizations"""
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Human Weakness Heatmap Analysis', fontsize=16, fontweight='bold')
        
        # 1. Time-based heatmap (Hour x Day of Week)
        if 'Time Pattern Analysis' in results and not results['Time Pattern Analysis'].empty:
            time_data = results['Time Pattern Analysis']
            pivot = time_data.pivot_table(index='hour_of_day', columns='day_of_week', 
                                         values='click_rate', fill_value=0)
            
            # Reorder days
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            existing_days = [day for day in day_order if day in pivot.columns]
            pivot = pivot[existing_days]
            
            sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd', 
                       ax=axes[0,0], cbar_kws={'label': 'Click Rate (%)'})
            axes[0,0].set_title('Click Rate by Hour and Day', fontweight='bold')
            axes[0,0].set_xlabel('Day of Week')
            axes[0,0].set_ylabel('Hour of Day')
        
        # 2. Device and Location Risk
        if 'Device and Location Risk' in results and not results['Device and Location Risk'].empty:
            device_data = results['Device and Location Risk']
            pivot = device_data.pivot_table(index='device_type', columns='location', 
                                           values='click_rate', fill_value=0)
            
            sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd',
                       ax=axes[0,1], cbar_kws={'label': 'Click Rate (%)'})
            axes[0,1].set_title('Click Rate by Device and Location', fontweight='bold')
            axes[0,1].set_xlabel('Location')
            axes[0,1].set_ylabel('Device Type')
        
        # 3. Department vulnerability
        if 'Department Vulnerability' in results and not results['Department Vulnerability'].empty:
            dept_data = results['Department Vulnerability']
            
            x = range(len(dept_data))
            axes[1,0].bar(x, dept_data['click_rate'], color='#ff6b6b', alpha=0.7, label='Click Rate')
            axes[1,0].bar(x, dept_data['credential_rate'], color='#ee5a6f', alpha=0.9, label='Credential Rate')
            
            axes[1,0].set_xticks(x)
            axes[1,0].set_xticklabels(dept_data['department'], rotation=45, ha='right')
            axes[1,0].set_ylabel('Rate (%)')
            axes[1,0].set_title('Department Vulnerability Comparison', fontweight='bold')
            axes[1,0].legend()
            axes[1,0].grid(axis='y', alpha=0.3)
        
        # 4. Risk factor impact
        if 'High Risk Combinations' in results and not results['High Risk Combinations'].empty:
            risk_data = results['High Risk Combinations'].head(10)
            
            y_pos = range(len(risk_data))
            axes[1,1].barh(y_pos, risk_data['click_rate'], color='#ff6b6b')
            axes[1,1].set_yticks(y_pos)
            
            labels = [f"{row['hour_of_day']}:00 {row['day_of_week'][:3]}\n{row['device_type']}" 
                     for _, row in risk_data.iterrows()]
            axes[1,1].set_yticklabels(labels, fontsize=8)
            axes[1,1].set_xlabel('Click Rate (%)')
            axes[1,1].set_title('Top 10 Highest Risk Scenarios', fontweight='bold')
            axes[1,1].grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        output_path = os.path.join(self.script_dir, 'human_weakness_heatmap.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"\n✓ Visualizations saved to '{output_path}'")
        plt.show()
    
    def generate_recommendations(self, results):
        """Generate actionable security recommendations"""
        print("\n" + "="*60)
        print("SECURITY RECOMMENDATIONS")
        print("="*60)
        
        recommendations = []
        
        # Analyze time patterns
        if 'Time Pattern Analysis' in results and not results['Time Pattern Analysis'].empty:
            time_data = results['Time Pattern Analysis']
            high_risk_hours = time_data[time_data['click_rate'] > 25]
            
            if not high_risk_hours.empty:
                peak_hour = high_risk_hours.loc[high_risk_hours['click_rate'].idxmax()]
                recommendations.append(
                    f"⚠️  Peak vulnerability at {int(peak_hour['hour_of_day'])}:00 on {peak_hour['day_of_week']} "
                    f"({peak_hour['click_rate']:.1f}% click rate)\n"
                    f"   → Schedule additional training for high-risk time windows\n"
                    f"   → Implement extra email filtering during these hours"
                )
        
        # Analyze device risks
        if 'Device and Location Risk' in results and not results['Device and Location Risk'].empty:
            device_data = results['Device and Location Risk']
            mobile_data = device_data[device_data['device_type'] == 'Mobile']
            
            if not mobile_data.empty:
                mobile_risk = mobile_data['click_rate'].mean()
                if mobile_risk > 20:
                    recommendations.append(
                        f"📱 Mobile devices show {mobile_risk:.1f}% average click rate\n"
                        f"   → Deploy mobile-specific security awareness training\n"
                        f"   → Consider mobile device management (MDM) solutions\n"
                        f"   → Implement additional verification for mobile access"
                    )
        
        # Analyze department vulnerabilities
        if 'Department Vulnerability' in results and not results['Department Vulnerability'].empty:
            dept_data = results['Department Vulnerability']
            vulnerable_dept = dept_data.loc[dept_data['click_rate'].idxmax()]
            
            recommendations.append(
                f"🏢 {vulnerable_dept['department']} department most vulnerable "
                f"({vulnerable_dept['click_rate']:.1f}% click rate)\n"
                f"   → Prioritize targeted training for this department\n"
                f"   → Review current security protocols and access levels\n"
                f"   → Assign security champions within the department"
            )
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"\n{i}. {rec}")
        else:
            print("\n✓ No critical vulnerabilities detected at this time")
        
        print("\n" + "="*60)
    
    def close(self):
        if self.conn:
            self.conn.close()
            print("\n✓ Database connection closed")

def main():
    analyzer = HumanWeaknessAnalyzer()
    
    print("Human Weakness Heatmap Analyzer")
    print("="*60)
    
    try:
        # Setup and generate data
        analyzer.setup_database()
        analyzer.generate_sample_data(num_employees=200, num_simulations=5000)
        
        # Run analysis
        results = analyzer.run_analysis()
        
        # Create visualizations
        analyzer.create_visualizations(results)
        
        # Generate recommendations
        analyzer.generate_recommendations(results)
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        analyzer.close()

if __name__ == "__main__":
    main()