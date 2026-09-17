# פערים שנותרו — EVulnTasker v1.0 Beta

עודכן: 15 בספטמבר 2026.

מסמך עבודה ליום הבא. מה שסומן כסגור נבדק בקוד ובטסטים. מה שנשאר הוא חוב אמיתי או בחירת מוצר שעדיין לא נסגרה.

---

## מה נסגר

- **Live Workflow** הוא המסווג היחיד למסכים (Main, Trends, Status, תורי השלבים, Incoming CVEs).
- **`INTEL_START_DATE`** חל על כל קליטה: Local, SMB, Exchange, ATOM, inline, webhooks, Debugger.
- **`status` / `pipeline_status`** נכתבים יחד דרך `apply_status`. Live Workflow נשאר המסווג למפעיל.
- **CMDB / Sonatype / ITNM** הוגדרו כמורים למלאי, לא כשלב בצינור. Matching קורא רק ל-Internal systems. סנכרון מרוחק מוסיף ציוד חדש בלבד, כבוי כברירת מחדל.
- **Debugger הוא dry-run.** לא נשלח מייל ולא נפתח טיקט. כל שלב מפורק: מה בוצע, למי הייתה התאמה ולמה (או למה לא), ואם הייתה התאמה — למי היה נשלח בקליטה אמיתית.
- **קידומת `EVULNTASKER_*`.** Settings, `.env.example`, systemd ו-setup כותבים את השם החדש. `VULNINTEL_*` עדיין נקרא מ-`.env` קיים. יחידת `systemd/vulnintel.service` הוסרה מהעץ; uninstall עדיין עוצר יחידות vaict/vulnintel ישנות על הדיסק אם נשארו.

---

## פערים פתוחים (לפי עדיפות)

### 1. אין מסך התחברות

הממשק פתוח לכל מי שמגיע לפורט (`0.0.0.0:8080`). אין משתמש, סיסמה, או תפקידים.

מתאים למעבדה פנימית. לא מתאים לחשיפה לרשת ארגונית רחבה בלי reverse proxy עם אימות.

### 2. Alembic בלי גרסאות

`setup.sh` מריץ `alembic upgrade head` רק אם יש קבצים תחת `alembic/versions/`. התיקייה ריקה. בפועל הסכמה עולה ב-`create_all` ו-`ALTER` חד-כיווני.

שדרוגים עובדים על הוספת עמודות. אין היסטוריית מיגרציות ל-PostgreSQL, אין downgrade, ואין העתקה אוטומטית מ-SQLite ל-PostgreSQL.

### 3. סנכרון CMDB / Sonatype / ITNM לא נבדק מול שרת חי

המתודולוגיה ברורה והקוד קיים (`INVENTORY_SYNC_ENABLED=false`, מרווח ברירת מחדל 24 שעות, הכנסת ציוד חדש בלבד). **Sonatype IQ** שולף אפליקציות וספריות מדוח הסריקה האחרון (`/api/v2/applications`, `/api/v2/reports/applications`, `/raw`) ומתחיל סנכרון ב-Save כש-Enable דלוק. אין ברשת הביתית CMDB / Sonatype / ITNM, ולכן החיבור החי לא אומת מול API אמיתי.

טפסי Settings (Enable, Test connection) נשארים להגדרה עתידית. עד שיהיה שרת לבדיקה — לא מדליקים.

### 4. Gmail Act מחוץ למסך Ticketing

`GMAIL_SENDER_EMAIL` / `GMAIL_APP_PASSWORD` / `GMAIL_RECEIVER_EMAIL` יושבים ב-`.env` בלבד. Settings→Ticketing מכסה Jira, Monday, Email (SMTP), CRM. Gmail הוא ערוץ נוסף בלי טופס.

### 5. Webhook ב-API בלי מסך

`POST /api/webhooks/{token}` קיים. אין טאב Feeds ל-webhook. שורות מקור ישנות מנוקות.

---

## מה לא פער

- Unmatched ב-Trends מול Live Workflow — יושר היום.
- קובץ מקומי / מייל מול `INTEL_START_DATE` — יושר היום (החלון חל על הכול).
- שני שדות סטטוס כמקור אמת למסכים — הכתיבה אוחדה; Live Workflow מסווג.
- CMDB כשלב בצינור — לא; הם מורים למלאי בלבד.
- Debugger שולח טיקט חי — לא; dry-run בלבד, עם הסבר התאמה ונמענים.
- קידומת `VULNINTEL_*` חובה — לא; `EVULNTASKER_*` נכתב, הישן נקרא.

---

## יום הבא (המלצה)

1. אם יש שרת Sonatype IQ — Enable + Save ב-Settings ואז Internal systems. CMDB/ITNM נשארים ל-CSV/24 שעות כשיהיה שרת.
2. מסך התחברות אם הפורט ייחשף מעבר למעבדה.
3. Alembic versions אם עוברים PostgreSQL עם היסטוריית סכימה.
