from pathlib import Path
import csv, random, re

random.seed(42)
OUT = Path(__file__).with_name("phishing_email_dataset.csv")
DOMAINS = ["example.com", "example.org", "example.net", "invalid.test"]

legit_templates = [
    ("university", "training@example.org", "University Workshop Reminder",
     "Hello student,\nThis is a reminder that the cybersecurity workshop is scheduled for Friday at 10:00 AM. No action is required."),
    ("hr", "hr@example.com", "HR Policy Update",
     "Hello team,\nThe updated leave policy is available in the employee portal. Please review it during your normal work schedule."),
    ("project", "project@example.org", "Project Status Update",
     "Hi team,\nThe project milestone review is scheduled for Monday. Please bring your current progress notes."),
    ("meeting", "calendar@example.net", "Meeting Reminder",
     "Hello,\nThis is a reminder for our project meeting tomorrow. The agenda is attached to the calendar invitation."),
    ("shopping", "orders@example.com", "Order Confirmation",
     "Thank you for your order. Your fictional order reference is DEMO-12345. This message contains no payment request."),
    ("newsletter", "news@example.org", "Monthly Newsletter",
     "Here is the monthly technology newsletter with articles and learning resources."),
    ("password", "account@example.net", "Password Change Confirmation",
     "Your password was changed successfully. If you made this change, no action is required. If not, contact support through the official portal."),
    ("bank-style", "alerts@example.com", "Demo Bank Account Notice",
     "This fictional bank-style notice is for training only. Your monthly statement is available in the official demo portal.")
]

phish_templates = [
    ("verification", "security-alert@account-check.invalid.test", "URGENT: Verify Your Account Immediately",
     "Dear customer,\nYour account will be suspended unless you verify your password immediately. Act now using http://198.51.100.10/verify-account"),
    ("invoice", "billing-alert@secure-check.invalid.test", "URGENT: Outstanding Invoice",
     "Your invoice is overdue. Confirm your payment details today or your service may be suspended. Visit http://198.51.100.10/payment"),
    ("prize", "winner@reward.invalid.test", "You Have Won a Reward",
     "Congratulations! You have won a prize. Claim your reward immediately at http://198.51.100.10/claim-reward"),
    ("password", "account-support@login.invalid.test", "Password Expires Today",
     "Your password expires today. Verify your credentials now at http://198.51.100.10/login"),
    ("delivery", "delivery-update@parcel.invalid.test", "Delivery Verification Required",
     "Your package could not be delivered. Confirm your personal details immediately at http://198.51.100.10/delivery"),
    ("hr", "hr-director@executive.invalid.test", "Urgent HR Request",
     "I need you to process this urgent payroll request immediately. Confirm personal information and payment details."),
    ("executive", "ceo@executive.invalid.test", "Confidential Payment Request",
     "This is urgent. Please arrange the requested payment today and send confirmation. Do not delay.")
]

rows = []
for i in range(600):
    is_phish = i % 2 == 0
    template = random.choice(phish_templates if is_phish else legit_templates)
    category, sender, subject, body = template
    if is_phish:
        urls = "http://198.51.100.10/" + random.choice(["verify-account","payment","claim-reward","login","delivery"])
        attachment = random.choice(["", "invoice.pdf.exe", "verification.js", "payment.zip"])
        label = "PHISHING"
    else:
        urls = random.choice(["", "https://example.org/info", "https://example.com/training"])
        attachment = random.choice(["", "agenda.pdf", "policy.pdf", "newsletter.txt"])
        label = "LEGITIMATE"
    rows.append({
        "email_id": f"DEMO-{i+1:04d}",
        "sender": sender,
        "sender_domain": sender.split("@")[-1],
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachment_name": attachment,
        "label": label,
        "category": category
    })

with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print(f"Generated {len(rows)} synthetic records at {OUT}")
