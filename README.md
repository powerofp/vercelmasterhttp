# راهنمای کامل راه‌اندازی پروژه روی Vercel

## 1) پیش‌نیازها

قبل از شروع، این موارد را داشته باشید:

- اکانت Vercel
- `git`
- `python` و `pip`
- `npm` (برای نصب Vercel CLI)

برای نصب `npm`، بهترین مسیر نصب Node.js است:

- صفحه رسمی دانلود Node.js: https://nodejs.org/en/download

بعد از نصب، بررسی کنید:

```bash
node -v
npm -v
```

## 2) دریافت پروژه

پروژه را clone کنید (یا ZIP دانلود کنید):

```bash
git clone https://github.com/block-p/vercelmasterhttp.git
cd MasterHttpRelayVPN
```

## 3) نصب Vercel CLI

```bash
npm i -g vercel
```

اگر به رجیستری اصلی دسترسی ندارید:

```bash
npm i -g vercel --registry="https://mirror-npm.runflare.com"
```

## 4) لاگین و دیپلوی روی Vercel
وارد فولدر vercel شوید.
ترتیب درست دستورات:

1. اول لاگین:

```bash
vercel login
```

2. داخل ریشه پروژه، یک deploy اولیه بزنید تا پروژه link شود:

```bash
vercel
```

این دستور معمولا Preview Deploy می‌سازد.

3. برای Production Deploy:

```bash
vercel --prod
```

## 5) تنظیم متغیر محیطی `AUTH_KEY` در Vercel

در داشبورد Vercel:

- `Project -> Settings -> Environment Variables -> Add`

مقدارها:

- `Key`: `AUTH_KEY`
- `Value`: یک کلید امن دلخواه (همین را بعدا در `config.json` هم می‌گذارید)

بعد از ذخیره، حتما Redeploy کنید (یا دوباره `vercel --prod` بزنید).

## 6) نکته مهم امنیتی Vercel

اگر Deployment Protection/Authentication روشن باشد، پروکسی به جای JSON صفحه HTML می‌گیرد و خطای `Bad JSON` می‌دهد.

در صورت نیاز:

- `Project -> Settings -> Deployment Protection`
- دسترسی/احراز هویت را برای دامنه‌ای که استفاده می‌کنید خاموش کنید.

## 7) نصب وابستگی‌های پایتون

پیشنهاد: ابتدا virtualenv بسازید.

```bash
python -m venv .venv
source .venv/bin/activate
```

سپس:

```bash
pip install -r requirements.txt
```

اگر نیاز به mirror داخلی دارید:

```bash
pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/
```

## 8) ساخت فایل تنظیمات

```bash
cp config.example.json config.json
```

نمونه پیشنهادی:

```json
{
  "mode": "vercel_edge",
  "front_domain": "YOUR_PROJECT.vercel.app",
  "front_ip": "",
  "worker_host": "YOUR_PROJECT.vercel.app",
  "relay_path": "/api/api",
  "auth_key": "SAME_VALUE_AS_VERCEL_AUTH_KEY",
  "enable_batch": false,
  "enable_h2": false,
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "INFO",
  "verify_ssl": true,
  "hosts": {}
}
```

توضیح فیلدهای مهم:

- `worker_host`: در صفحه `Overview` پروژه Vercel، بخش `Domains` (بدون `https://`)
- `auth_key`: باید دقیقا برابر `AUTH_KEY` در Vercel باشد
- `front_domain`: برای شروع بهتر است همان `worker_host` باشد
- `front_ip`: معمولا خالی بگذارید
- `relay_path`: چون فایل شما `api/api.js` است باید `/api/api` باشد

## 9) اجرای پروژه

```bash
python main.py
```

در اولین اجرا، در پوشه `ca/` گواهی ساخته می‌شود.

## 10) نصب گواهی CA (برای HTTPS ضروری است)

### macOS

1. فایل `ca/ca.crt` را باز کنید (Keychain Access).
2. روی گواهی دوبار کلیک کنید.
3. بخش `Trust` را باز کنید.
4. گزینه `When using this certificate` را روی `Always Trust` بگذارید.
5. مرورگر را کامل ببندید و دوباره باز کنید.

### Windows

1. روی `ca/ca.crt` دوبار کلیک کنید.
2. `Install Certificate`
3. Store: `Trusted Root Certification Authorities`
4. مرورگر را کامل ری‌استارت کنید.

### Linux (Ubuntu/Debian)

```bash
sudo cp ca/ca.crt /usr/local/share/ca-certificates/masterhttp-relay.crt
sudo update-ca-certificates
```

بعد مرورگر را ری‌استارت کنید.

### Firefox (همه سیستم‌عامل‌ها)

Firefox معمولا CA سیستم را کامل استفاده نمی‌کند. باید دستی import کنید:

1. `Settings -> Privacy & Security -> Certificates -> View Certificates`
2. تب `Authorities` -> `Import`
3. فایل `ca/ca.crt`
4. گزینه `Trust this CA to identify websites` را فعال کنید.

## 11) استفاده از پروکسی

بعد از اجرا، پروکسی HTTP روی `127.0.0.1:8085` بالا می‌آید.

در مرورگر/سیستم:

- Proxy Host: `127.0.0.1`
- Proxy Port: `8085`
- Type: `HTTP`

## 12) تست سریع سلامت

تست endpoint روی Vercel:

```bash
curl -sS "https://YOUR_PROJECT.vercel.app/api/api" \
  -H "content-type: application/json" \
  --data '{"k":"YOUR_AUTH_KEY","m":"GET","u":"https://example.com","h":{},"r":true}'
```

اگر خروجی شامل `s`, `h`, `b` بود، relay درست کار می‌کند.

---

تمام.
