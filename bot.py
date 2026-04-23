import requests
from bs4 import BeautifulSoup
import time
import json
import os

# ===== CONFIG =====
BOT_TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "keywords": [
        "Generative AI Intern",
        "AI Intern",
        "Machine Learning Intern",
        "Python Developer Intern"
    ],
    "location": "Remote OR Coimbatore OR Tamil Nadu",
    "experience": "0-1",
    "batch": "2026/2027",
    "interval_hours": 24
}

# ===== LOAD CONFIG =====
if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)

with open(CONFIG_FILE) as f:
    config = json.load(f)

sent_jobs = set()

# ===== TELEGRAM SEND =====
def send_telegram(msg):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    requests.post(url, data={"chat_id": CHAT_ID, "text": msg})


# ===== FETCH JOBS =====
def fetch_jobs():
    jobs_found = []

    for keyword in config["keywords"]:
        url = f"https://www.linkedin.com/jobs/search/?keywords={keyword}&location={config['location']}"
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            res = requests.get(url, headers=headers)
            soup = BeautifulSoup(res.text, "html.parser")

            jobs = soup.find_all("div", class_="base-card")

            for job in jobs[:8]:
                title = job.find("h3").text.strip()
                company = job.find("h4").text.strip()
                link = job.find("a")["href"]

                location_tag = job.find("span", class_="job-search-card__location")
                location = location_tag.text.strip() if location_tag else "Not Mentioned"

                # Basic experience filter
                if any(x in title.lower() for x in ["senior", "lead", "manager"]):
                    continue

                job_id = link

                if job_id not in sent_jobs:
                    sent_jobs.add(job_id)

                    message = f"""
🚀 ROLE: {title}

🏢 COMPANY: {company}

📍 LOCATION: {location}

🎓 ELIGIBILITY: Batch {config['batch']} (Fresher)

📊 EXPERIENCE: {config['experience']} years

💰 SALARY: Not disclosed (typical 4–8 LPA for freshers)

🔗 APPLY LINK:
{link}

-------------------------
"""
                    jobs_found.append(message)

        except Exception as e:
            print("Error:", e)

    return jobs_found


# ===== MAIN =====
def run_bot():
    print("Checking jobs...")
    jobs = fetch_jobs()

    if jobs:
        send_telegram(f"📢 Job Alerts for YOU (Batch {config['batch']})\n")
        for job in jobs:
            send_telegram(job)
            time.sleep(2)
    else:
        send_telegram("❌ No new jobs found today.")


# ===== LOOP =====
while True:
    run_bot()
    print("Sleeping...")
    time.sleep(config["interval_hours"] * 3600)
