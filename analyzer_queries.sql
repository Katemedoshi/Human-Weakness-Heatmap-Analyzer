-- Human Weakness Analysis Queries
-- These queries identify when and why humans fail security tests

-- QUERY: Time Pattern Analysis
-- Shows vulnerability by hour and day of week
SELECT 
    hour_of_day,
    day_of_week,
    COUNT(*) as total_simulations,
    SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) as clicks,
    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
    SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) as credentials_provided,
    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate,
    ROUND(AVG(CASE WHEN time_to_click_seconds IS NOT NULL 
              THEN time_to_click_seconds END), 1) as avg_seconds_to_click
FROM phishing_simulations
GROUP BY hour_of_day, day_of_week
HAVING total_simulations >= 5
ORDER BY click_rate DESC
LIMIT 20;

-- QUERY: Device and Location Risk
-- Analyzes how device and location impact vulnerability
SELECT 
    device_type,
    location,
    COUNT(*) as total_simulations,
    SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) as clicks,
    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate
FROM phishing_simulations
GROUP BY device_type, location
ORDER BY click_rate DESC;

-- QUERY: Department Vulnerability
-- Shows which departments are most susceptible
SELECT 
    e.department,
    COUNT(DISTINCT e.employee_id) as employee_count,
    COUNT(ps.simulation_id) as total_simulations,
    SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) as total_clicks,
    ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as click_rate,
    ROUND(100.0 * SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as credential_rate,
    ROUND(AVG(e.security_training_score), 1) as avg_training_score,
    ROUND(AVG(e.tenure_months), 1) as avg_tenure_months
FROM employees e
JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
GROUP BY e.department
ORDER BY click_rate DESC;

-- QUERY: High Risk Combinations
-- Identifies specific combinations of factors that lead to failures
SELECT 
    hour_of_day,
    day_of_week,
    device_type,
    location,
    COUNT(*) as simulations,
    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate
FROM phishing_simulations
GROUP BY hour_of_day, day_of_week, device_type, location
HAVING simulations >= 3
ORDER BY click_rate DESC, credential_rate DESC
LIMIT 15;

-- QUERY: Employee Risk Profile
-- Identifies repeat offenders and patterns
SELECT 
    e.employee_code,
    e.department,
    e.tenure_months,
    e.security_training_score,
    COUNT(ps.simulation_id) as total_simulations,
    SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) as times_clicked,
    ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as personal_click_rate,
    SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) as times_gave_credentials,
    CASE 
        WHEN 100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id) >= 50 
        THEN 'HIGH RISK'
        WHEN 100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id) >= 25 
        THEN 'MEDIUM RISK'
        ELSE 'LOW RISK'
    END as risk_category
FROM employees e
JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
GROUP BY e.employee_id
HAVING times_clicked >= 2
ORDER BY personal_click_rate DESC, times_gave_credentials DESC
LIMIT 20;

-- QUERY: Temporal Vulnerability Trends
-- Shows how vulnerability changes throughout the week
SELECT 
    CASE 
        WHEN day_of_week IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday') THEN 'Weekday'
        ELSE 'Weekend'
    END as period_type,
    CASE 
        WHEN hour_of_day BETWEEN 6 AND 11 THEN 'Morning (6-11)'
        WHEN hour_of_day BETWEEN 12 AND 13 THEN 'Lunch (12-13)'
        WHEN hour_of_day BETWEEN 14 AND 17 THEN 'Afternoon (14-17)'
        WHEN hour_of_day BETWEEN 18 AND 22 THEN 'Evening (18-22)'
        ELSE 'Night (23-5)'
    END as time_period,
    COUNT(*) as simulations,
    ROUND(100.0 * SUM(CASE WHEN clicked_link THEN 1 ELSE 0 END) / COUNT(*), 1) as click_rate,
    ROUND(AVG(CASE WHEN time_to_click_seconds IS NOT NULL 
              THEN time_to_click_seconds END), 1) as avg_time_to_click
FROM phishing_simulations
GROUP BY period_type, time_period
ORDER BY click_rate DESC;

-- QUERY: Training Effectiveness
-- Correlates training scores with actual behavior
SELECT 
    CASE 
        WHEN e.security_training_score >= 90 THEN '90-100 (Excellent)'
        WHEN e.security_training_score >= 80 THEN '80-89 (Good)'
        WHEN e.security_training_score >= 70 THEN '70-79 (Fair)'
        ELSE '60-69 (Poor)'
    END as training_score_range,
    COUNT(DISTINCT e.employee_id) as employees,
    COUNT(ps.simulation_id) as total_simulations,
    ROUND(100.0 * SUM(CASE WHEN ps.clicked_link THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as click_rate,
    ROUND(100.0 * SUM(CASE WHEN ps.provided_credentials THEN 1 ELSE 0 END) / COUNT(ps.simulation_id), 1) as credential_rate
FROM employees e
JOIN phishing_simulations ps ON e.employee_id = ps.employee_id
GROUP BY training_score_range
ORDER BY training_score_range DESC;

-- QUERY: Response Speed Analysis
-- Faster clicks often indicate less scrutiny
SELECT 
    CASE 
        WHEN time_to_click_seconds <= 10 THEN '0-10 sec (Instant)'
        WHEN time_to_click_seconds <= 30 THEN '11-30 sec (Quick)'
        WHEN time_to_click_seconds <= 60 THEN '31-60 sec (Normal)'
        WHEN time_to_click_seconds <= 120 THEN '61-120 sec (Slow)'
        ELSE '120+ sec (Very Slow)'
    END as response_time,
    COUNT(*) as clicks,
    ROUND(100.0 * SUM(CASE WHEN provided_credentials THEN 1 ELSE 0 END) / COUNT(*), 1) as credential_rate
FROM phishing_simulations
WHERE clicked_link = 1 AND time_to_click_seconds IS NOT NULL
GROUP BY response_time
ORDER BY 
    CASE response_time
        WHEN '0-10 sec (Instant)' THEN 1
        WHEN '11-30 sec (Quick)' THEN 2
        WHEN '31-60 sec (Normal)' THEN 3
        WHEN '61-120 sec (Slow)' THEN 4
        ELSE 5
    END;