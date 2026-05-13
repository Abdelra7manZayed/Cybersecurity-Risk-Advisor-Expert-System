# Cybersecurity Risk Advisor Expert System

## Project Description

The **Cybersecurity Risk Advisor Expert System** is a rule-based knowledge-based system developed in Python using the **Experta** library. It helps users assess cybersecurity risks based on selected security indicators such as weak passwords, missing MFA, outdated operating systems, ransomware detection, public Wi-Fi usage, and failed login attempts.

The system does not only calculate a risk score. It also explains why each risk was detected, shows a confidence score using the Certainty Factor approach, and gives practical security recommendations.

## Project Files

| File | Description |
|---|---|
| `Cybersecurity_Risk_Advisor.ipynb` | Academic Jupyter Notebook with explanation, Experta implementation, test cases, and interactive widgets. |
| `app.py` | Streamlit web application version of the expert system. |
| `requirements.txt` | Required Python libraries. |
| `README.md` | Project documentation and running instructions. |

## Features

- Rule-based cybersecurity risk assessment.
- Knowledge base containing risks, conditions, severity levels, confidence values, and advice.
- Experta `KnowledgeEngine` implementation.
- Forward chaining inference.
- Rule priority using salience.
- Certainty Factor calculation.
- Overall risk score from 0 to 100.
- Final classification into Low, Medium, High, and Critical Risk.
- Explanation trace showing fired rules.
- Interactive Jupyter Notebook widgets.
- Professional Streamlit web app.

## Technologies Used

- Python 3
- Experta
- Streamlit
- ipywidgets
- Jupyter Notebook

## How to Install Requirements

Open a terminal or PowerShell in the project folder and run:

```bash
pip install -r requirements.txt
```

If you are using a virtual environment on Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## How to Run the Notebook

```bash
jupyter notebook Cybersecurity_Risk_Advisor.ipynb
```

Then run the notebook cells from top to bottom. The interactive widget section allows you to select cybersecurity indicators, set confidence values, and click **Analyze Cybersecurity Risk**.

## How to Run the Streamlit App

```bash
streamlit run app.py
```

The web app will open in your browser. Use the sidebar to select security indicators and press **Analyze Cybersecurity Risk**.

## Example Inputs

### Example 1: Medium Risk

- Suspicious Email Clicked = selected
- Low Security Awareness = selected
- Confidence values = 0.80

Expected output: Phishing Attack Risk with Medium severity.

### Example 2: High Risk

- Weak Password = selected
- No MFA = selected
- Failed Login Attempts = 8

Expected output: Account Compromise Risk and Brute Force Attack Risk.

### Example 3: Critical Risk

- Ransomware Detected = selected
- No Backup = selected
- Data Breach = selected

Expected output: Critical overall cybersecurity risk.

## Academic Explanation

### Project Overview

This project is a knowledge-based expert system that evaluates cybersecurity risk using a set of predefined expert rules. The system receives facts from the user, matches them with the rules in the knowledge base, fires the applicable rules, and generates a final cybersecurity risk report.

### Why This Is an Expert System

It is an expert system because it contains the main expert system components:

- A **knowledge base** that stores expert cybersecurity rules.
- A **fact base** that stores user-selected cybersecurity indicators.
- An **inference engine** that applies rules to facts.
- An **explanation system** that explains the reasoning process.
- A **recommendation output** that gives practical advice.

### Knowledge Base Explanation

The knowledge base contains cybersecurity risks such as account compromise, malware infection, phishing, ransomware, data breach, brute force attack, and remote access exposure. Each risk has:

- Conditions required to detect the risk.
- Severity level.
- Rule confidence value.
- Explanation reason.
- Recommended security advice.

### Inference Mechanism

The system uses the Experta inference engine. When the user provides facts, Experta compares these facts with rule patterns. If the required conditions are satisfied, the corresponding rule fires and adds a detected risk to the final report.

### Forward Chaining Explanation

Forward chaining starts from available facts and moves forward toward conclusions. In this project, the user selects facts such as `weak_password` and `no_mfa`. The engine then checks which rules match these facts and produces conclusions such as `Account Compromise Risk`.

### Salience Explanation

Salience is used to control rule priority. Critical rules such as ransomware and data breach have the highest salience, so they are evaluated before less critical risks. This makes the reasoning process closer to real cybersecurity triage, where critical incidents must be handled first.

### Certainty Factor Explanation

The system applies Certainty Factor manually using this equation:

```text
final_cf = rule_cf × min(cf1, cf2)
```

`rule_cf` represents the confidence of the expert rule. `cf1` and `cf2` represent the confidence values of the selected facts. The minimum value is used because a rule with multiple conditions should not be more confident than its weakest evidence.

### Explanation System

Every fired rule is stored in an explanation trace. The trace shows:

- Which rule fired.
- What risk was detected.
- Why the risk was detected.
- The severity level.
- The confidence score.
- The recommended advice.

### Difference Between This System and a Normal If-Else Program

A normal if-else program usually checks conditions in a fixed sequence written directly in the code. This expert system separates knowledge from control. The knowledge base contains rules, and the inference engine decides which rules match the facts. It also supports rule priority, pattern matching, confidence scoring, and explanation tracing, which makes it more suitable for expert reasoning.

### Conclusion

The Cybersecurity Risk Advisor Expert System demonstrates how knowledge-based systems can be applied to cybersecurity risk assessment. It uses facts, rules, forward chaining, salience, certainty factors, and explanation tracing to produce a clear and practical cybersecurity report. The project includes both an academic notebook and a Streamlit web application, making it suitable for presentation, discussion, and practical demonstration.
