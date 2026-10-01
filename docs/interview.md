# Interview Preparation — 10 Questions and Strong Student Answers

## 1. Explain your project.
I built a defensive Phishing Email Detection and Awareness Dashboard. It accepts synthetic email sender, subject, body, URLs, and an attachment filename, analyzes multiple phishing indicators, produces a 0–100 risk score, explains the reasons, stores safe analysis metadata in SQLite, and visualizes analytics in Streamlit. I also added an optional TF-IDF and Logistic Regression model and automated tests.

## 2. What is phishing?
Phishing is a social-engineering technique where a message attempts to make a person perform an unsafe action, such as revealing information, clicking a link, or opening an attachment. My project focuses on detecting indicators rather than assuming one signal proves phishing.

## 3. Why did you use multiple indicators?
A single signal can create false positives. For example, a legitimate HR message can be urgent. Combining sender, content, URL, and attachment signals gives more context and makes the explanation more useful.

## 4. How does your URL analyzer work?
It parses URLs as strings. It checks the scheme, hostname, length, subdomains, raw IP usage, shortener patterns, suspicious keywords, and unusual characters. It never visits the URL.

## 5. What is feature engineering here?
Feature engineering converts email evidence into structured values such as urgency count, credential keyword count, URL count, IP URL flag, uppercase ratio, and attachment risk. These features can support rule-based scoring and future ML models.

## 6. How did you calculate the risk score?
I used project-defined weights. For example, a suspicious sender adds 15, urgency adds 10, a credential request adds 20, a suspicious URL adds 20, and a suspicious attachment adds 25. The score is capped at 100. These are assumptions that need calibration before production use.

## 7. Why are precision and recall important?
Precision tells me how many flagged messages are actually phishing in the evaluated dataset, while recall tells me how much of the phishing class the detector catches. Both matter because too many false alarms can cause alert fatigue, while missed phishing can be risky.

## 8. What is a false positive and false negative?
A false positive is a legitimate email incorrectly flagged. A false negative is a phishing email incorrectly treated as legitimate. My project deliberately demonstrates both limitations because detection is not perfect.

## 9. How would a SOC analyst use this?
The analyst could use it for initial triage: inspect the sender, URL structure, attachment metadata, content indicators, and risk explanation, then perform human review and choose the appropriate response. The automated score supports the analyst rather than replacing the analyst.

## 10. What security controls did you implement?
I restricted the project to synthetic/authorized data, never execute attachments, never visit URLs, limit upload size and extensions, validate API input, avoid storing raw email bodies by default, use environment variables for configuration, and document HTTPS, authentication, authorization, and rate limiting as production requirements.
