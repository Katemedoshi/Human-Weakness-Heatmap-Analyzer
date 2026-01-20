import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
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
        
        self.conn.commit()
        print("✓ Database schema created")
    
    def import_employees_csv(self, filepath):
        """Import employee data from CSV"""
        try:
            df = pd.read_csv(filepath)
            
            # Validate required columns
            required_cols = ['employee_code', 'department']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                print(f"❌ Missing required columns: {missing_cols}")
                print(f"   Required: employee_code, department")
                print(f"   Optional: tenure_months, security_training_score")
                return False
            
            # Add default values for optional columns
            if 'tenure_months' not in df.columns:
                df['tenure_months'] = 12
            if 'security_training_score' not in df.columns:
                df['security_training_score'] = 75.0
            
            # Insert into database
            cursor = self.conn.cursor()
            for idx, row in df.iterrows():
                cursor.execute('''
                    INSERT OR IGNORE INTO employees 
                    (employee_code, department, tenure_months, security_training_score)
                    VALUES (?, ?, ?, ?)
                ''', (row['employee_code'], row['department'], 
                      row['tenure_months'], row['security_training_score']))
            
            self.conn.commit()
            print(f"✓ Imported {len(df)} employees from {filepath}")
            return True
            
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            return False
        except Exception as e:
            print(f"❌ Error importing employees: {str(e)}")
            return False
    
    def import_simulations_csv(self, filepath):
        """Import phishing simulation data from CSV"""
        try:
            df = pd.read_csv(filepath)
            
            # Validate required columns
            required_cols = ['employee_code', 'timestamp', 'device_type', 
                           'location', 'clicked_link']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                print(f"❌ Missing required columns: {missing_cols}")
                print(f"   Required: employee_code, timestamp, device_type, location, clicked_link")
                print(f"   Optional: provided_credentials, time_to_click_seconds")
                return False
            
            # Add default values for optional columns
            if 'provided_credentials' not in df.columns:
                df['provided_credentials'] = False
            if 'time_to_click_seconds' not in df.columns:
                df['time_to_click_seconds'] = None
            
            cursor = self.conn.cursor()
            imported = 0
            
            for idx, row in df.iterrows():
                # Get employee_id from employee_code
                cursor.execute('SELECT employee_id FROM employees WHERE employee_code = ?', 
                             (row['employee_code'],))
                result = cursor.fetchone()
                
                if not result:
                    print(f"⚠️  Employee {row['employee_code']} not found, skipping simulation")
                    continue
                
                employee_id = result[0]
                
                # Parse timestamp
                try:
                    ts = pd.to_datetime(row['timestamp'])
                    day_of_week = ts.strftime('%A')
                    hour_of_day = ts.hour
                except:
                    print(f"⚠️  Invalid timestamp format for row {idx}, skipping")
                    continue
                
                # Convert boolean
                clicked = str(row['clicked_link']).lower() in ['true', '1', 'yes']
                provided_creds = str(row['provided_credentials']).lower() in ['true', '1', 'yes']
                
                cursor.execute('''
                    INSERT INTO phishing_simulations 
                    (employee_id, timestamp, day_of_week, hour_of_day, device_type, 
                     location, clicked_link, provided_credentials, time_to_click_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (employee_id, ts.strftime('%Y-%m-%d %H:%M:%S'), day_of_week, 
                      hour_of_day, row['device_type'], row['location'], 
                      clicked, provided_creds, row['time_to_click_seconds']))
                
                imported += 1
            
            self.conn.commit()
            print(f"✓ Imported {imported} phishing simulations from {filepath}")
            return True
            
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            return False
        except Exception as e:
            print(f"❌ Error importing simulations: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def manual_entry_mode(self):
        """Interactive mode for manual data entry"""
        print("\n" + "="*60)
        print("MANUAL DATA ENTRY")
        print("="*60)
        
        while True:
            print("\n1. Add Employee")
            print("2. Add Phishing Simulation")
            print("3. View Current Data")
            print("4. Back to Main Menu")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == '1':
                self.add_employee_manual()
            elif choice == '2':
                self.add_simulation_manual()
            elif choice == '3':
                self.view_current_data()
            elif choice == '4':
                break
            else:
                print("Invalid option, try again")
    
    def add_employee_manual(self):
        """Add a single employee manually"""
        print("\n--- Add Employee ---")
        
        employee_code = input("Employee Code (e.g., EMP001): ").strip()
        department = input("Department (e.g., Engineering, Sales): ").strip()
        tenure_months = input("Tenure in months (default 12): ").strip() or "12"
        training_score = input("Security training score (0-100, default 75): ").strip() or "75"
        
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO employees (employee_code, department, tenure_months, security_training_score)
                VALUES (?, ?, ?, ?)
            ''', (employee_code, department, int(tenure_months), float(training_score)))
            self.conn.commit()
            print(f"✓ Employee {employee_code} added successfully")
        except sqlite3.IntegrityError:
            print(f"❌ Employee {employee_code} already exists")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def add_simulation_manual(self):
        """Add a single phishing simulation manually"""
        print("\n--- Add Phishing Simulation ---")
        
        # Show available employees
        cursor = self.conn.cursor()
        cursor.execute('SELECT employee_code, department FROM employees LIMIT 10')
        employees = cursor.fetchall()
        
        if not employees:
            print("❌ No employees found. Please add employees first.")
            return
        
        print("\nAvailable employees (showing first 10):")
        for emp in employees:
            print(f"  - {emp[0]} ({emp[1]})")
        
        employee_code = input("\nEmployee Code: ").strip()
        
        # Verify employee exists
        cursor.execute('SELECT employee_id FROM employees WHERE employee_code = ?', (employee_code,))
        result = cursor.fetchone()
        if not result:
            print(f"❌ Employee {employee_code} not found")
            return
        
        employee_id = result[0]
        
        print("\nSimulation Details:")
        timestamp_str = input("Timestamp (YYYY-MM-DD HH:MM:SS) or press Enter for now: ").strip()
        if not timestamp_str:
            timestamp = datetime.now()
        else:
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except:
                print("❌ Invalid timestamp format")
                return
        
        device_type = input("Device Type (Desktop/Mobile/Tablet): ").strip() or "Desktop"
        location = input("Location (Office/Remote/Coffee Shop/Airport): ").strip() or "Office"
        clicked_link = input("Clicked Link? (yes/no): ").strip().lower() == 'yes'
        provided_credentials = False
        time_to_click = None
        
        if clicked_link:
            provided_credentials = input("Provided Credentials? (yes/no): ").strip().lower() == 'yes'
            time_str = input("Time to click in seconds (or press Enter to skip): ").strip()
            if time_str:
                try:
                    time_to_click = int(time_str)
                except:
                    pass
        
        try:
            cursor.execute('''
                INSERT INTO phishing_simulations 
                (employee_id, timestamp, day_of_week, hour_of_day, device_type, 
                 location, clicked_link, provided_credentials, time_to_click_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (employee_id, timestamp.strftime('%Y-%m-%d %H:%M:%S'), 
                  timestamp.strftime('%A'), timestamp.hour, device_type, 
                  location, clicked_link, provided_credentials, time_to_click))
            self.conn.commit()
            print("✓ Simulation added successfully")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def view_current_data(self):
        """Display current data summary"""
        cursor = self.conn.cursor()
        
        print("\n--- Data Summary ---")
        
        cursor.execute('SELECT COUNT(*) FROM employees')
        emp_count = cursor.fetchone()[0]
        print(f"Total Employees: {emp_count}")
        
        cursor.execute('SELECT COUNT(*) FROM phishing_simulations')
        sim_count = cursor.fetchone()[0]
        print(f"Total Simulations: {sim_count}")
        
        if sim_count > 0:
            cursor.execute('''
                SELECT 
                    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate
                FROM phishing_simulations
            ''')
            click_rate = cursor.fetchone()[0]
            print(f"Overall Click Rate: {click_rate}%")
        
        print("\nRecent Employees:")
        cursor.execute('SELECT employee_code, department FROM employees ORDER BY employee_id DESC LIMIT 5')
        for row in cursor.fetchall():
            print(f"  - {row[0]} ({row[1]})")
    
    def create_sample_csv_templates(self):
        """Create CSV template files for users"""
        # Employee template
        employee_template = pd.DataFrame({
            'employee_code': ['EMP001', 'EMP002', 'EMP003'],
            'department': ['Engineering', 'Sales', 'Marketing'],
            'tenure_months': [24, 12, 36],
            'security_training_score': [85.5, 72.0, 90.0]
        })
        employee_template.to_csv('employee_template.csv', index=False)
        
        # Simulation template
        simulation_template = pd.DataFrame({
            'employee_code': ['EMP001', 'EMP001', 'EMP002'],
            'timestamp': ['2024-01-15 09:30:00', '2024-01-16 14:45:00', '2024-01-15 16:20:00'],
            'device_type': ['Desktop', 'Mobile', 'Desktop'],
            'location': ['Office', 'Coffee Shop', 'Remote'],
            'clicked_link': [True, True, False],
            'provided_credentials': [False, True, False],
            'time_to_click_seconds': [45, 12, None]
        })
        simulation_template.to_csv('simulation_template.csv', index=False)
        
        print("✓ Created template files:")
        print("  - employee_template.csv")
        print("  - simulation_template.csv")
    
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
                HAVING total_simulations >= 3
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
                HAVING simulations >= 2
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
                HAVING times_clicked >= 1
                ORDER BY personal_click_rate DESC
                LIMIT 20
            '''
        }
    
    def run_analysis(self):
        """Execute SQL analysis queries"""
        # Check if we have data
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM phishing_simulations')
        if cursor.fetchone()[0] == 0:
            print("\n⚠️  No simulation data available for analysis")
            return {}
        
        print("\n" + "="*60)
        print("HUMAN WEAKNESS HEATMAP ANALYSIS")
        print("="*60)
        
        results = {}
        queries = self.get_analysis_queries()
        
        for query_name, query in queries.items():
            try:
                df = pd.read_sql_query(query, self.conn)
                if not df.empty:
                    results[query_name] = df
                    print(f"\n{query_name}")
                    print("-" * 60)
                    print(df.to_string(index=False))
                else:
                    print(f"\n{query_name}")
                    print("-" * 60)
                    print("No data available")
            except Exception as e:
                print(f"\n❌ Error in {query_name}: {str(e)}")
        
        return results
    
    def create_visualizations(self, results):
        """Generate heatmaps and visualizations"""
        if not results:
            print("\n⚠️  No data available for visualization")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Human Weakness Heatmap Analysis', fontsize=16, fontweight='bold')
        
        # 1. Time-based heatmap
        if 'Time Pattern Analysis' in results and not results['Time Pattern Analysis'].empty:
            time_data = results['Time Pattern Analysis']
            pivot = time_data.pivot_table(index='hour_of_day', columns='day_of_week', 
                                         values='click_rate', fill_value=0)
            
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            existing_days = [day for day in day_order if day in pivot.columns]
            if existing_days:
                pivot = pivot[existing_days]
            
            sns.heatmap(pivot, annot=True, fmt='.1f', cmap='YlOrRd', 
                       ax=axes[0,0], cbar_kws={'label': 'Click Rate (%)'})
            axes[0,0].set_title('Click Rate by Hour and Day', fontweight='bold')
            axes[0,0].set_xlabel('Day of Week')
            axes[0,0].set_ylabel('Hour of Day')
        else:
            axes[0,0].text(0.5, 0.5, 'Insufficient Time Data', ha='center', va='center')
            axes[0,0].set_title('Click Rate by Hour and Day', fontweight='bold')
        
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
        else:
            axes[0,1].text(0.5, 0.5, 'Insufficient Device Data', ha='center', va='center')
            axes[0,1].set_title('Click Rate by Device and Location', fontweight='bold')
        
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
        else:
            axes[1,0].text(0.5, 0.5, 'Insufficient Department Data', ha='center', va='center')
            axes[1,0].set_title('Department Vulnerability Comparison', fontweight='bold')
        
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
            axes[1,1].set_title('Top Risk Scenarios', fontweight='bold')
            axes[1,1].grid(axis='x', alpha=0.3)
        else:
            axes[1,1].text(0.5, 0.5, 'Insufficient Combination Data', ha='center', va='center')
            axes[1,1].set_title('Top Risk Scenarios', fontweight='bold')
        
        plt.tight_layout()
        output_path = os.path.join(self.script_dir, 'human_weakness_heatmap.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"\n✓ Visualizations saved to '{output_path}'")
        plt.show()
    
    def generate_recommendations(self, results):
        """Generate actionable security recommendations"""
        if not results:
            return
        
        print("\n" + "="*60)
        print("SECURITY RECOMMENDATIONS")
        print("="*60)
        
        recommendations = []
        
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
        
        if 'Device and Location Risk' in results and not results['Device and Location Risk'].empty:
            device_data = results['Device and Location Risk']
            mobile_data = device_data[device_data['device_type'] == 'Mobile']
            
            if not mobile_data.empty:
                mobile_risk = mobile_data['click_rate'].mean()
                if mobile_risk > 20:
                    recommendations.append(
                        f"📱 Mobile devices show {mobile_risk:.1f}% average click rate\n"
                        f"   → Deploy mobile-specific security awareness training\n"
                        f"   → Consider mobile device management (MDM) solutions"
                    )
        
        if 'Department Vulnerability' in results and not results['Department Vulnerability'].empty:
            dept_data = results['Department Vulnerability']
            vulnerable_dept = dept_data.loc[dept_data['click_rate'].idxmax()]
            
            recommendations.append(
                f"🏢 {vulnerable_dept['department']} department most vulnerable "
                f"({vulnerable_dept['click_rate']:.1f}% click rate)\n"
                f"   → Prioritize targeted training for this department\n"
                f"   → Assign security champions within the department"
            )
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"\n{i}. {rec}")
        else:
            print("\n✓ No critical vulnerabilities detected")
        
        print("\n" + "="*60)
    
    def close(self):
        if self.conn:
            self.conn.close()

def main():
    print("="*60)
    print("HUMAN WEAKNESS HEATMAP ANALYZER")
    print("="*60)
    
    analyzer = HumanWeaknessAnalyzer()
    analyzer.setup_database()
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Import Data from CSV Files")
        print("2. Manual Data Entry")
        print("3. Generate Sample CSV Templates")
        print("4. Run Analysis & Generate Visualizations")
        print("5. View Current Data Summary")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            print("\n--- Import CSV Files ---")
            emp_file = input("Employee CSV file path (or press Enter to skip): ").strip()
            if emp_file:
                analyzer.import_employees_csv(emp_file)
            
            sim_file = input("Simulation CSV file path (or press Enter to skip): ").strip()
            if sim_file:
                analyzer.import_simulations_csv(sim_file)
        
        elif choice == '2':
            analyzer.manual_entry_mode()
        
        elif choice == '3':
            analyzer.create_sample_csv_templates()
        
        elif choice == '4':
            results = analyzer.run_analysis()
            if results:
                analyzer.create_visualizations(results)
                analyzer.generate_recommendations(results)
        
        elif choice == '5':
            analyzer.view_current_data()
        
        elif choice == '6':
            print("\nExiting...")
            analyzer.close()
            break
        
        else:
            print("❌ Invalid option, please try again")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()