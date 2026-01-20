# 🔒 Human Weakness Heatmap Analyzer

**A Behavioral Cybersecurity Analytics Platform**

> *Security breaches don’t start with malware. They start with people.*

The **Human Weakness Heatmap Analyzer** is a data-driven cybersecurity analytics system that identifies **when, where, and why humans fail phishing simulations**.
Instead of counting attacks, this project analyzes **human behavior patterns** across time, devices, departments, and environments.

Built with **Python, SQL, SQLite, Streamlit, and advanced analytics**, this project is designed to impress security teams, data analysts, and interviewers alike.

---

## 🎯 Problem Statement

Traditional cybersecurity dashboards focus on:

* Number of attacks
* Malware detection
* Firewall metrics

They rarely answer the harder questions:

* **At what time are employees most vulnerable?**
* **Does mobile usage increase risk?**
* **Which departments need targeted training?**
* **Do faster clicks indicate weaker judgment?**

This project answers those questions using **behavioral data**.

---

## 🧠 Key Insights This System Uncovers

* Temporal vulnerability patterns (hour, day, weekday vs weekend)
* Device and location risk profiling
* Department-wise susceptibility analysis
* High-risk behavioral combinations
* Individual employee risk profiling
* Correlation between training scores and real behavior
* Response speed vs credential compromise risk

---

## 🏗️ Architecture Overview

```
Human Weakness Heatmap Analyzer
│
├── SQLite Database
│   ├── employees
│   └── phishing_simulations
│
├── SQL Analytics Layer
│   ├── Time-based risk queries
│   ├── Device & location risk queries
│   ├── Department vulnerability queries
│   ├── Employee risk profiling queries
│
├── Python Analytics Engine
│   ├── Data ingestion (CSV / manual / synthetic)
│   ├── Behavioral scoring logic
│   ├── Aggregation & statistics
│
├── Visualization Layer
│   ├── Heatmaps
│   ├── Bar charts
│   └── Risk tables
│
└── Streamlit Dashboard
    ├── Interactive UI
    ├── Upload & generate data
    ├── Live insights & recommendations
```

---

## 📊 Features

### 🔹 Data Management

* Generate realistic **synthetic phishing data**
* Upload CSVs for real-world simulations
* Manual data entry mode
* Download CSV templates

### 🔹 Behavioral Analytics

* Time pattern vulnerability analysis
* Device & location risk heatmaps
* Department-level risk scoring
* High-risk scenario detection
* Repeat offender identification
* Training effectiveness correlation

### 🔹 Visualization

* Hour × Day heatmaps
* Device × Location heatmaps
* Department vulnerability charts
* Employee risk tables with color coding

### 🔹 Actionable Recommendations

The system automatically generates insights such as:

* High-risk time windows
* Mobile device vulnerability alerts
* Most vulnerable departments
* Training prioritization suggestions

---

## 🗃️ Database Schema

### `employees`

| Column                  | Description                  |
| ----------------------- | ---------------------------- |
| employee_id             | Primary key                  |
| employee_code           | Unique employee identifier   |
| department              | Employee department          |
| tenure_months           | Employment duration          |
| security_training_score | Training effectiveness score |
| created_at              | Record creation timestamp    |

### `phishing_simulations`

| Column                | Description                             |
| --------------------- | --------------------------------------- |
| simulation_id         | Primary key                             |
| employee_id           | Foreign key                             |
| timestamp             | Simulation time                         |
| day_of_week           | Day name                                |
| hour_of_day           | Hour (0–23)                             |
| device_type           | Desktop / Mobile / Tablet               |
| location              | Office / Remote / Coffee Shop / Airport |
| clicked_link          | Boolean                                 |
| provided_credentials  | Boolean                                 |
| time_to_click_seconds | Reaction speed                          |

---

## 🧪 SQL Analysis Highlights

The project includes advanced SQL queries such as:

* **Time Pattern Analysis**
  Identifies peak vulnerability hours and days

* **Device & Location Risk**
  Detects risk amplification due to mobile usage or public locations

* **Department Vulnerability**
  Ranks departments by real-world failure rates

* **High-Risk Combinations**
  Finds dangerous combinations of time + device + location

* **Employee Risk Profiles**
  Flags repeat offenders with risk categorization

* **Response Speed Analysis**
  Faster clicks = higher credential compromise risk

---

## 🖥️ Streamlit Dashboard

### Tabs

* 📊 Overview
* ⏰ Time Patterns
* 📱 Device & Location
* 👥 Departments & Employees

### Metrics Displayed

* Total employees
* Total simulations
* Click-through rate
* Credential compromise rate

---

## 🚀 How to Run the Project

### 1️⃣ Install Dependencies

```bash
pip install streamlit pandas numpy matplotlib seaborn
```

### 2️⃣ Run the Streamlit App

```bash
streamlit run app.py
```

### 3️⃣ Choose a Data Source

* Generate sample data
* Upload CSV files
* Manual entry

---

## 📁 CSV Templates

The system can auto-generate:

* `employee_template.csv`
* `simulation_template.csv`

These templates ensure clean imports and correct schema alignment.

---

## 🧠 Why This Project Stands Out

✔ Focuses on **human behavior**, not just attacks
✔ Combines **SQL + Python + Visualization + Product thinking**
✔ Interview-ready with real-world applicability
✔ Privacy-friendly (runs fully locally)
✔ Easily extensible to ML or LLM-based risk prediction

---

## 🔮 Future Enhancements

* Predictive ML model for human risk scoring
* LLM-based explanation of risky behavior
* Personalized training recommendations
* Organization-wide risk forecasting
* Integration with SIEM tools

---

## 🏁 Final Note

This project treats cybersecurity as a **human problem first**, a technical problem second.

If malware is the weapon,
**human behavior is the trigger.**

And this system maps exactly where that trigger is weakest. 🔍🔒


