# קטלוג פונקציונליות — EVulnTasker

**EVulnTasker** (Elizarov Vulnerabilities Tasking Manager Platform) היא מערכת RBVM (ניהול פגיעויות מבוסס סיכון) לשרת Linux. היא קולטת מודיעין CVE מקבצים, דוא"ל ופידי ATOM, מחלצת מזהים, מעשירה לפי בחירה מ-NVD/EPSS, מתאימה vendor/product לקטלוג **Internal systems** המקומי, ופותחת משימות לבעלי נכסים ולצוות ציד (Jira, Monday.com, דוא"ל או CRM פנימי). באותו שלב Act נוצרים גם חוקי Sigma ושאילתות SIEM.

הממשק **באנגלית בלבד**. אין מסך התחברות.

מדריך התקנה והפעלה באנגלית: [`README.md`](README.md). פערים שנותרו: [`GAPS.md`](GAPS.md).

---

## 1. ליבת האפליקציה והרצה

### הרצת השירות והדפסת כתובות מקומיות

**תיאור:** מפעיל את האפליקציה מתוך venv (`python3 app.py`), טוען את חבילת `app/`, ומדפיס כתובות מקומיות (localhost ו-IP ברשת). ברירת מחדל: `0.0.0.0:8080`.

**למה זה נדרש:** סביבת בדיקה או ייצור בפקודה אחת, עם כתובת ברורה לממשק.

**ספריות Python:** ספריית התקן (`importlib`, `socket`, `os`, `sys`, `pathlib`); **Uvicorn** כשרת ASGI.

### שרת Web / API

**תיאור:** REST תחת `/api` ודפי HTML. תהליך אחד מריץ HTTP, worker של ה-pipeline ו-scheduler.

**מסכים:** Main, Status, Internal systems, Incoming CVEs, Input Sources, Extraction, Enrichment, Asset matching, Actions, Debugger, Settings, ופרטי CVE.

**למה זה נדרש:** ממשק העבודה של אנליסטים ומפעילי SOC.

**ספריות Python:** **FastAPI**, **Starlette**, **Uvicorn**, **Jinja2**, **python-multipart**, **orjson**.

### הגדרות סביבה

**תיאור:** טוען קונפיגורציה מ-`.env` / משתני סביבה. רוב המתגים נשמרים גם מ-Settings (Database, Feeds, Enrichment, Internet intel, AI, Ticketing).

**למה זה נדרש:** התאמה לסביבת הארגון בלי לשנות קוד.

**ספריות Python:** **Pydantic**, **pydantic-settings**.

### לוגים

**תיאור:** כותב לוגים ל-stderr ולקבצים מסתובבים, כולל לוג מובנה.

**למה זה נדרש:** חקירת תקלות, ביקורת, ומעקב אחרי כשלים ב-pipeline.

**ספריות Python:** ספריית התקן `logging`; **structlog**.

### התקנה, systemd והסרה

**תיאור:** `setup.sh` / `uninstall.sh` / `package_offline.sh`, יחידת systemd בשם `evulntasker`, התקנה ברירת מחדל ב-`/opt/evulntasker`, גיבוי DB בהסרה. אחרי שינוי קוד Python: `sudo systemctl restart evulntasker`.

**למה זה נדרש:** פריסה יציבה על RHEL בלי תלות ב-IDE.

**ספריות Python:** Bash + systemd; האפליקציה עצמה רצה ב-Python.

---

## 2. מסד הנתונים

### אחסון כל נתוני המערכת

**תיאור:** שומר CVEs, מקורות, נכסים (Internal systems), כרטיסים, ארטיפקטי זיהוי, לוג ביקורת והיסטוריית ריצות. ברירת מחדל: SQLite (`data/evulntasker.db`). בייצור: PostgreSQL.

**למה זה נדרש:** מקור אמת אחד לכל מחזור החיים של CVE.

**ספריות Python:** **SQLAlchemy 2**, **Alembic**, **psycopg2-binary**, **greenlet**; SQLite דרך מנהל התקן מובנה.

### בחירת DB בהגדרות (SQLite / PostgreSQL מקומי / PostgreSQL חיצוני)

**תיאור:** טאב Database: SQLite, PostgreSQL על אותו שרת Linux (`127.0.0.1` או Unix socket), או שרת מרוחק. שומר `EVULNTASKER_DATABASE_URL` (ומעדכן `VULNINTEL_DATABASE_URL` אם הוא כבר בקובץ). בודק חיבור, מחליף engine ויוצר טבלאות. נתונים קיימים ב-SQLite אינם מועתקים אוטומטית.

**למה זה נדרש:** ניסוי על קובץ מקומי; ייצור על PostgreSQL ארגוני.

**ספריות Python:** **SQLAlchemy**, **psycopg2-binary**, **Pydantic**.

### איפוס נתוני עבודה

**תיאור:** Settings → Reset. שני כפתורים נפרדים, כל אחד עם אישור לפני מחיקה. **Reset Internal systems** מוחק את קטלוג המערכות הפנימיות ואת קישורי ההתאמה. **Delete all CVEs** מוחק את Incoming CVEs (כולל היסטוריית pipeline, כרטיסים וזיהויים). לא מוחק חיבור DB, מקורות קלט והגדרות אינטגרציה.

**למה זה נדרש:** חזרה למלאי ריק או לתור CVE ריק בלי להתקין מחדש ובלי למחוק את שניהם יחד.

**ספריות Python:** **SQLAlchemy** (`app/services/wipe.py`).

### שדרוג סכימה אוטומטי

**תיאור:** ב-startup יוצר טבלאות חסרות ומוסיף עמודות חדשות לקובץ SQLite קיים.

**למה זה נדרש:** `create_all` לא מוסיף עמודות לטבלה שכבר קיימת.

**ספריות Python:** **SQLAlchemy** (`inspect`, `ALTER TABLE`).

---

## 3. צינור העיבוד (Pipeline) — חמישה שלבים

### תזמור הצינור (Orchestrator)

**תיאור:** לכל אירוע קליטה מריץ את חמשת השלבים לפי הסדר. CVE שכבר במסד מדלג על enrich/match/act (למעט רענון ATOM). כשל לא ניתן לשחזור מסומן `FAILED` עם traceback. קובץ מקומי/SMB נשמר כאירוע ingest גם אם כל ה-CVE כבר ידועים (`skipped`).

**למה זה נדרש:** זרימה אחידה ממודיעין עד פעולה, בלי לאבד תיעוד של קובץ שנקלט.

**ספריות Python:** **SQLAlchemy**; **asyncio** לתור העבודה.

### שלב 1 — קליטה (Ingest)

**תיאור:** Local folder, SMB/CIFS, Outlook/Exchange, ATOM/RSS. לא מוחק קבצים אחרי קליטה. קובץ מקומי/SMB שלא השתנה (גודל/זמן) מדולג כל עוד כל ה-CVE שלו עדיין במסד או בתור; אם מחקו CVE, הקובץ נקרא שוב. שומר `IngestEvent` ויוצר `Vulnerability` אם ה-CVE חדש. עדכון מודיעין באינטרנט מגיע מ-NVD/ATOM, לא מסריקה חוזרת של אותו קובץ. `INTEL_START_DATE` חוסם קליטה מכל מקור — קבצים מקומיים, SMB, דוא"ל, ATOM, הזנה ידנית, webhook וגם Debugger.

**למה זה נדרש:** מודיעין מגיע מקבצים, מייל ופידים; צריך נקודת כניסה אחת.

**ספריות Python:** **smbprotocol**, **exchangelib**, **httpx**, **SQLAlchemy**. נתיב `POST /api/webhooks/{token}` עדיין קיים בקוד, בלי מסך Settings; מקורות webhook ישנים מנוקים.

### שלב 2 — חילוץ (Extract)

**תיאור:** מחלץ CVE ב-regex, וגם vendor / product / version מטקסט מסומן, CSV, JSON או CPE. LLM נקרא רק אם לא נמצא מזהה CVE ו-AI modules דלוק.

**למה זה נדרש:** קבצים ומיילים לא מגיעים בפורמט אחיד.

**ספריות Python:** ספריית התקן `re`, `csv`, `json`; **httpx** ל-AI.

### שלב 3 — העשרה (Enrich)

**תיאור:** מתג עצמאי (`ENRICHMENT_ENABLED`). כבוי: מדלגים על NVD/EPSS ועל שכתוב AI וממשיכים להתאמה. דלוק: NVD 2.0 ואז EPSS לפי Enable lookup. Timeout או כשל רשת לא מסמנים FAILED — ה-CVE נשאר **Waiting for intel** ב-Live Workflow (עם סיבת NVD/EPSS והמועד לניסיון הבא) עד שיש vendor/product/ציונים; Matching וטיקטים מחכים. שכתוב תיאור לטיקט רק אם AI דלוק **וגם** המצב הוא **EVulnTasker AI**. מצב **Org LLM only** לא משכתב ב-Enrichment.

**למה זה נדרש:** דירוג סיכון (חומרה + סבירות ניצול) בלי לחייב LLM או גישה לאינטרנט.

**ספריות Python:** **httpx**, **tenacity**.

### שלב 4 — התאמה לנכסים (Match)

**תיאור:** חיפוש vendor/product מול קטלוג **Internal systems** המקומי בלבד (ידני, CSV, או ציוד חדש שנלמד מ-CMDB / Sonatype / ITNM). CVE של ליבת Linux פוגע גם בשורות distro (Red Hat / Ubuntu וכו'). בלי זהות (vendor/product) אין התאמה. אחרי חפיפת שם, גרסת הקטלוג חייבת לחפוף את שדה הגרסה או משפחת `N.x` בטקסט האדבייזורי (`22.x` מכסה `22.7R2.4`; `9.0` לבד לא מכסה 22.x). טוקן כללי יחיד כמו `secure` אינו מספיק למוצר. אם אין התאמה ו-AI דלוק — המודל עשוי להציע בעלים, בלי ליצור שורת מלאי מזויפת. CMDB / Sonatype / ITNM אינם שלב בצינור — הם מלמדים את הקטלוג בנפרד.

**למה זה נדרש:** פגיעות בלי בעלים לא מטופלת.

**ספריות Python:** **SQLAlchemy**; **httpx** ל-AI.

### שלב 5 — פעולה (Act)

**תיאור:** לכל ספק Ticketing שדלוק נפתחות משימות בעלים וציד לפי תבניות **Message**. מייצר Sigma ו-KQL / XQL / AQK / EKQL. דוא"ל לבעלים לפי `owner_email` במערכת הפנימית; **Permanent email** לציד אם מלא; fallback owner רק כשהשדה ריק. AI לא נדרש לפתיחת טיקט. בלי אף ספק דלוק — נוצרים רק זיהויים.

**למה זה נדרש:** להניע טיפול וציד, לא רק לדווח.

**ספריות Python:** **httpx** (Jira / Monday / CRM), **aiosmtplib** (SMTP), **exchangelib**, תבניות מובנות ל-Sigma/SIEM.

### AI — מתג גלובלי ושני מצבי Enrichment

**תיאור:**

| מצב | משמעות |
|------|---------|
| **Disable** (AI modules) | אין קריאות LLM בכל הצינור. טיקטים עדיין נפתחים |
| **EVulnTasker AI** | אחרי NVD/EPSS המודל עשוי לשכתב תיאור לבעלים ולהשלים שדות |
| **Org LLM only** | אין שכתוב ב-Enrichment בתוך EVulnTasker; Extract/Match עדיין יכולים להשתמש במודל |

ספק אחד בלבד: Gemini, ChatGPT, Azure OpenAI, GitHub Copilot.

**למה זה נדרש:** ארגון יכול לאסור LLM לגמרי, או להשאיר שכתוב לארגון עצמו.

**ספריות Python:** **httpx** מול API תואם OpenAI (`/chat/completions`).

---

## 4. מקורות מודיעין

### תיקייה מקומית בשרת

**תיאור:** סורק נתיב על ה-Linux של EVulnTasker (לא נתיב במחשב האנליסט). כל קובץ מופיע ב-Extraction, גם אם הוסיף CVE יחיד או שכל המזהים כבר היו במסד.

**למה זה נדרש:** בדיקות ידניות והטמעה בלי תלות ברשת.

**ספריות Python:** ספריית התקן `pathlib`.

### SMB / CIFS (משתמש AD/LDAP)

**תיאור:** שיתוף קבצים ארגוני, כמה מיקומים, אותו חשבון. קבצי טקסט (txt/csv/json/md).

**למה זה נדרש:** עדכוני ספקים שמגיעים כתיקיית רשת.

**ספריות Python:** **smbprotocol**.

### Outlook / Exchange מקומי

**תיאור:** מאזין לתיבת on-prem, סורק מיילים לא נקראים ל-CVE, ויכול לשלוח התראות.

**למה זה נדרש:** התרעות ספקים שמגיעות רק בדוא"ל.

**ספריות Python:** **exchangelib**.

### ATOM / RSS

**תיאור:** פידים מתוזמנים (ברירת מחדל: CISA, Ubuntu, Microsoft MSRC, Exploit-DB). Settings שומר URL ומרווח. Enable/Pause לכל פיד ו-Sync now חיים ב-Input Sources. Pause חוסם רק משיכה אוטומטית; Sync now מושך גם פיד מושהה. NVD ו-EPSS נשארים lookups. כפוף לאותו `INTEL_START_DATE` כמו שאר המקורות.

**למה זה נדרש:** מודיעין ציבורי ב-pull בלי סורק חיצוני.

**ספריות Python:** **httpx**, **APScheduler**.

### דילוג על CVE קיים

**תיאור:** אם ה-CVE כבר במסד — לא מריצים שוב enrich/match/act. ATOM יכול לרענן. קובץ מקומי עדיין נשמר כאירוע.

**למה זה נדרש:** למנוע כפילויות בכרטיסים, בלי להעלים את הקובץ ממסך Extraction.

**ספריות Python:** **SQLAlchemy**.

---

## 5. ממשק משתמש (UI)

### Main / Status

**תיאור:** Main — KPI לפי שלבי הצינור, עם חותמת Updated שמתעדכנת כל 30 שניות. Status — תור חי: שלב, סטטוס, עדיפות, צוות, קישור טיקט, ופאנל מצב אינטגרציות.

**למה זה נדרש:** תמונת מצב תפעולית: מה בתהליך, מה נכשל, מה הסתיים.

**ספריות Python:** **Jinja2** + JS מול **FastAPI**.

### Internal systems / Incoming CVEs

**תיאור:** קטלוג מוצרים פנימי שנבנה בהגדרה (הוספה ידנית או CSV: vendor, product, type, version, owner, email, team). CMDB / ITNM דוגמים לפי לוח זמנים (ברירת מחדל 24 שעות) ומוסיפים **רק ציוד חדש**. Sonatype IQ, כשמדליקים Save, שולף אפליקציות וספריות מדוח הסריקה האחרון של כל אפליקציה. Incoming CVEs — כל ה-CVE שנשמרו, עם חיתוך תאים ארוכים ו-tooltip. לחיצה על שורה פורסת תחנות Live Workflow; מזהה ה-CVE פותח את הכרטיס המלא. בשני המסכים אפשר לבחור שורות ולמחוק רק אותן (Select to delete → סימון → OK).

**למה זה נדרש:** מלאי להתאמה, ומסד של כל מה שנקלט.

**ספריות Python:** **FastAPI**, **SQLAlchemy**.

### Input Sources / Extraction / Enrichment / Matching / Actions

**תיאור:** ניטור מקורות עם Enable/Pause ו-Sync now. ATOM מופעל לפי URL. NVD/EPSS Enable הוא lookup בשלב Enrichment. אירועי ingest (שורה לקובץ/פריט פיד) ורשומות CVE; תורי שלב שנשארים אחרי שה-CVE התקדם; Actions מציג טיקט בעלים, ציד וזיהויים.

**למה זה נדרש:** לעקוב אחרי כל תחנה בנפרד.

**ספריות Python:** **Jinja2** + JS; נתונים מ-**SQLAlchemy**.

### Debugger

**תיאור:** Debugger — הרצת CVE (או טקסט מדומה של קובץ מקומי) דרך כל השלבים, עם פירוק מה בוצע בכל שלב, למי הייתה התאמה ולמה (או למה לא), ולמי היה נשלח טיקט בקליטה אמיתית. לא נשמר כלום ולא נשלח כלום. CVE מחוץ ל-`INTEL_START_DATE` נעצר ולא רץ.

**למה זה נדרש:** מעקב מקצה לקצה ולימוד למה שלב דולג או נכשל.

**ספריות Python:** **FastAPI**, **Jinja2**.

### הגדרות (Settings)

**תיאור:** טאבים: Database, Reset, Feeds, Enrichment, Internet intel, AI modules, Inventory, Ticketing, Message.

**למה זה נדרש:** חיבור לסביבה הארגונית בלי לערוך קבצים ידנית.

**ספריות Python:** **FastAPI**, **Pydantic**, **SQLAlchemy**, **smbprotocol**, **exchangelib**, **httpx**, **aiosmtplib**.

### מיתוג וניווט

**תיאור:** כותרת EVulnTasker v1.0 Beta, תג AI-Powered RBVM, אייקון, תפריט צד עם קבוצות Overview / Databases / Pipeline / System.

**למה זה נדרש:** זיהוי המוצר וניווט.

**ספריות Python:** HTML/CSS/JS סטטיים דרך **Starlette** / **FastAPI**.

---

## 6. אינטגרציות חיצוניות

| מודול | תיאור | למה נדרש | ספריות Python |
|--------|--------|-----------|----------------|
| **NVD 2.0** | שליפת רשומת CVE (CVSS, CWE, CPE) כש-Enrichment ו-Enable lookup דלוקים | מקור האמת לחומרה | **httpx**, **tenacity** |
| **EPSS (FIRST)** | ציון סבירות ניצול | מיון לפי סיכון ולא רק CVSS | **httpx**, **tenacity** |
| **Jira** | משימות בעלים וציד (Enable נפרד) | העברת אחריות | **httpx** |
| **Monday.com** | אותו Act על לוח Monday | צוותים שעובדים ב-Monday | **httpx** |
| **Email (SMTP)** | טיקטים בדוא"ל דרך ממסר | מעבדה / נמענים חיצוניים | **aiosmtplib** |
| **Internal CRM** | API משימות פנימי | מערכת כרטיסים של הארגון | **httpx** |
| **Exchange** | קליטת מייל ושליחת התראה | מודיעין והתראה | **exchangelib** |
| **SMB** | קבצים משיתוף ארגוני | מודיעין כקבצים | **smbprotocol** |
| **AI Copilot** | חילוץ / שכתוב / בעלות ב-JSON, רק אם AI דלוק | פערים בלי לשבור את הצינור | **httpx** |
| **SIEM / Sigma** | חוקי ציד (Sigma, KQL, XQL, AQK, EKQL) | שאילתות מוכנות לצוות הציד | תבניות Python מובנות |
| **CMDB / Sonatype / ITNM** | מורים למלאי. CMDB/ITNM: דגימה מחזורית. Sonatype IQ: אפליקציות + ספריות מדוח אחרון, גם ב-Save. הכנסת ציוד חדש בלבד. לא חלק מהצינור | בניית הקטלוג בנפרד מ-CVE | **httpx** |

---

## 7. מודלי נתונים עיקריים

### Vulnerability

**תיאור:** רשומת CVE הקנונית: מזהה, תיאור, CVSS/EPSS, יצרן/מוצר/גרסה, סטטוס צינור, דגלי שימוש ב-AI.

**למה זה נדרש:** האובייקט שכל המסכים והשלבים עובדים עליו.

**ספריות Python:** **SQLAlchemy**.

### PipelineStatus

**תיאור:** `INGESTED`, `EXTRACTED`, `ENRICHED`, `MATCHED`, `ACTIONED`, `AI_FALLBACK`, `FAILED`.

**למה זה נדרש:** תצפית אחידה בממשק וב-API.

**ספריות Python:** `enum` + **SQLAlchemy**.

### AuditLog

**תיאור:** יומן לכל מעבר שלב: הודעה, שלב, JSON ב-`details`, חותמת זמן. התערבות AI מודגשת.

**למה זה נדרש:** לענות על "מה קרה ל-CVE הזה ולמה".

**ספריות Python:** **SQLAlchemy**.

### מקורות, אירועי קליטה, ריצות, נכסים, כרטיסים, זיהויים

**תיאור:** קונפיגורציית מקורות, payload גולמי (כולל `filename` לקובץ), היסטוריית ריצה, התאמות נכסים, מפתחות טיקט (כולל dry-run) וארטיפקטי Sigma/SIEM.

**למה זה נדרש:** מעקב מקצה לקצה ומניעת כפילויות בלי להעלים קבצים.

**ספריות Python:** **SQLAlchemy**.

---

## 8. עיבוד רקע

### תור עבודה בתוך התהליך

**תיאור:** אחרי שמירת האירוע ב-DB, ה-worker באותו תהליך מריץ את ה-orchestrator. אחרי ריסטארט אוסף אירועים שלא הסתיימו.

**למה זה נדרש:** לא לחסום HTTP בזמן NVD/Jira, ולא לאבד עבודה בריסטארט.

**ספריות Python:** **asyncio**.

### תזמון (Scheduler)

**תיאור:** סורק במרווחים רק פידים ש-Enable דלוק ב-Input Sources.

**למה זה נדרש:** מקורות pull לא דוחפים לבד.

**ספריות Python:** **APScheduler**.

### Celery + Redis (אופציונלי)

**תיאור:** אותה עבודת pipeline על כמה מכונות. לא חובה בהתקנת ברירת מחדל.

**ספריות Python:** **Celery**, **Redis**.

---

## 9. אמינות ותצפית

### Dry-run לפי ספק Ticketing

**תיאור:** אם ספק דלוק אבל לא מוגדר (אין URL/טוקן/SMTP) — נשמר כרטיס dry-run והצינור מסתיים. כיבוי הספק = אין טיקט ממנו. AI כבוי אינו dry-run: פשוט אין LLM, והטיקט נפתח מהתבניות.

**למה זה נדרש:** הדגמות ובדיקות בלי סודות, בלי לעצור את הצינור.

**ספריות Python:** לוגיקת האפליקציה + לקוחות האינטגרציה במצב לא מוגדר.

### ניסיונות חוזרים

**תיאור:** NVD/EPSS מנסים שוב אחרי כשל רשת זמני.

**למה זה נדרש:** APIs ציבוריים נופלים מדי פעם.

**ספריות Python:** **tenacity**.

### Debugger

**תיאור:** מריץ CVE (או טקסט לדוגמה) דרך כל שלב עם המודול והפונקציה, לפי המתגים החיים ב-Settings. כל שלב מפורק: מה בוצע, למי הייתה התאמה ולמה — או למה לא הייתה התאמה — ואם הייתה התאמה, למי היה נשלח טיקט בקליטה אמיתית. Debugger לא שומר רשומות ולא שולח מייל או כרטיס. אם ה-CVE מחוץ ל-`INTEL_START_DATE` — העיבוד נעצר, כמו בכל מקור אחר.

**למה זה נדרש:** ללמוד למה Enrichment דולג, למה אין match, ולמי היה נשלח טיקט — בלי לפתוח כרטיס אמיתי.

**ספריות Python:** **FastAPI**, **SQLAlchemy**.

---

## סיכום ספריות צד-שלישי (`requirements.txt`)

| חבילה | תפקיד |
|--------|--------|
| **FastAPI** | REST API ומסגרת האפליקציה |
| **Uvicorn** | שרת ASGI |
| **Starlette** | תשתיות HTTP (דרך FastAPI) |
| **Jinja2** | תבניות HTML |
| **python-multipart** | פרסור טפסים |
| **orjson** | JSON מהיר |
| **Pydantic** / **pydantic-settings** | ולידציה וקונפיגורציית `.env` |
| **SQLAlchemy 2** | ORM (SQLite / PostgreSQL) |
| **Alembic** | מיגרציות סכימה |
| **psycopg2-binary** | מנהל התקן PostgreSQL (Python &lt; 3.14) |
| **greenlet** | תמיכה ב-SQLAlchemy |
| **httpx** | NVD, EPSS, Jira, Monday, CRM, AI |
| **aiohttp** | HTTP אסינכרוני |
| **APScheduler** | סריקה מתוזמנת |
| **exchangelib** | Exchange / Outlook |
| **aiosmtplib** | ממסר SMTP |
| **smbprotocol** | SMB/CIFS (AD/LDAP) |
| **python-dateutil** | פרסור תאריכים |
| **tenacity** | ניסיונות חוזרים ל-NVD / EPSS |
| **structlog** | לוג מובנה |
| **Celery** + **Redis** | עובדים מבוזרים (אופציונלי) |
| **pytest** / **pytest-asyncio** | בדיקות |
