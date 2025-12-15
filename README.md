# Smart IP Blocker for Cloudflare v2.0

A professional PHP-based security log analysis system with modern glassmorphism UI, featuring automatic detection of malicious IP addresses and Cloudflare integration.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![PHP](https://img.shields.io/badge/PHP-7.4+-purple)
![License](https://img.shields.io/badge/license-MIT-green)

## 🏗️ Project Structure

```
smart-ip-blocker-for-cloudflare/
├── public/                     # Web root (point your server here)
│   ├── index.php              # Dashboard controller
│   ├── login.php              # Login controller
│   ├── cron.php               # Cron endpoint
│   ├── .htaccess              # Apache config
│   └── assets/
│       └── css/
│           └── style.css      # Glassmorphism theme
│
├── src/                        # Application source code
│   ├── Core/
│   │   ├── Application.php    # Bootstrap & DI container
│   │   ├── Auth.php           # Authentication handler
│   │   ├── View.php           # Template renderer
│   │   └── Logger.php         # Activity logger
│   └── Services/
│       ├── LogAnalyzer.php    # Log analysis service
│       ├── BlocklistManager.php # Threat feed management
│       └── CloudflareService.php # Cloudflare API
│
├── config/                     # Configuration files
│   ├── app.php                # Main configuration
│   └── blocklists.php         # Threat feed URLs
│
├── templates/                  # View templates
│   ├── layout.php             # Base layout
│   ├── login.php              # Login page
│   └── dashboard.php          # Main dashboard
│
├── data/                       # Data storage
│   ├── cache/                 # Cached blocklists
│   └── logs/                  # Application logs
│
├── vendor/
│   └── autoload.php           # PSR-4 autoloader
│
├── composer.json              # Package definition
└── README.md
```

## ✨ Features

- **Modern Architecture** - PSR-4 autoloading, separation of concerns, dependency injection
- **Glassmorphism UI** - Beautiful dark theme with glass effects and animations
- **Secure Authentication** - Session-based login with timeout protection
- **31+ Threat Feeds** - Comprehensive threat intelligence integration
- **Cloudflare Integration** - Automatic IP list updates
- **Cron Endpoint** - API for automated analysis
- **Activity Logging** - Track all actions
- **Log Parsing** - Regex-based parsing supporting Apache/Nginx access log formats
- **Blocklist Caching** - 24-hour intelligent caching to reduce API calls
- **CIDR Support** - Expands IP ranges (CIDR notation) to individual addresses
- **IPv6 Support** - Handles IPv6 addresses with GMP-based expansion
- **IP Whitelisting** - Built-in Cloudflare IP ranges to prevent false positives
- **HTML Reports** - Generates detailed HTML reports of suspicious activity

## 🚀 Quick Start

### 1. Configure Web Server

Point your web server's document root to the `public/` directory.

**Apache:**
```apache
DocumentRoot /path/to/smart-ip-blocker-for-cloudflare/public
```

**Nginx:**
```nginx
root /path/to/smart-ip-blocker-for-cloudflare/public;
index index.php;

location / {
    try_files $uri $uri/ /index.php?$query_string;
}

location ~ \.php$ {
    fastcgi_pass unix:/var/run/php/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    include fastcgi_params;
}
```

### 2. Set Permissions

```bash
chmod -R 755 data/
chmod -R 755 data/cache/
chmod -R 755 data/logs/
```

### 3. Configure Application

Edit `config/app.php`:

```php
'auth' => [
    'username' => 'your-username',
    'password_hash' => password_hash('your-password', PASSWORD_BCRYPT),
    'cron_secret' => 'your-secure-random-key',
],
```

### 4. Access Dashboard

Open `https://your-domain.com/` and login with your credentials.

**Default credentials:**
- Username: `admin`
- Password: `seclog2024!`

## ⚙️ Configuration

### Main Config (`config/app.php`)

| Section | Key | Description |
|---------|-----|-------------|
| `app.name` | Application name | Displayed in UI |
| `app.debug` | Debug mode | Enable for development |
| `auth.username` | Login username | Change in production! |
| `auth.password_hash` | Password hash | Use `password_hash()` |
| `auth.session_timeout` | Session duration | Default: 3600 (1 hour) |
| `auth.cron_secret` | Cron API key | Secret for automation |
| `cloudflare.*` | CF credentials | API token, account ID, list ID |

### Blocklists (`config/blocklists.php`)

Add or remove threat intelligence feeds as needed.

## 📡 API Endpoints

### Cron Endpoint

```bash
# Basic analysis
curl "https://domain.com/cron.php?key=YOUR_KEY"

# With Cloudflare push
curl "https://domain.com/cron.php?key=YOUR_KEY&cloudflare=1"

# Custom log file
curl "https://domain.com/cron.php?key=YOUR_KEY&log=/path/to/log"

# Text format output
curl "https://domain.com/cron.php?key=YOUR_KEY&format=text"
```

**Response:**
```json
{
  "success": true,
  "timestamp": "2024-12-15 13:00:00",
  "data": {
    "log_file": "/var/www/nginx.access.log",
    "lines_analyzed": 15234,
    "suspicious_count": 42,
    "suspicious_ips": ["1.2.3.4", "5.6.7.8"],
    "cloudflare": {
      "success": true,
      "added": 42
    }
  }
}
```

## 🎨 Architecture

### Core Classes

| Class | Purpose |
|-------|---------|
| `Application` | Singleton bootstrap, configuration, DI container |
| `Auth` | Authentication, sessions, cron key verification |
| `View` | Template rendering with data injection |
| `Logger` | File-based activity logging |

### Services

| Service | Purpose |
|---------|---------|
| `LogAnalyzer` | Parse logs, detect threats, manage bans |
| `BlocklistManager` | Fetch, cache, and query threat feeds |
| `CloudflareService` | Push IPs to Cloudflare lists |

## 🔒 Security

1. **Change default credentials** immediately
2. **Use HTTPS** in production
3. **Secure cron key** with strong random value
4. **Restrict directory access** with proper permissions
5. **Keep PHP updated** for security patches

## 📋 Requirements

- PHP 7.4+
- Extensions: `curl`, `json`, `filter`
- Optional: `gmp` (for IPv6 CIDR expansion)

## 🐛 Troubleshooting

**Login not working:**
- Clear browser cookies
- Check session directory permissions
- Verify password hash in config

**Blocklists not downloading:**
- Check `curl` extension
- Verify outbound HTTPS access
- Check `data/cache/` permissions

**Cloudflare errors:**
- Verify API token permissions
- Check account ID and list ID
- Review API response in logs

**Memory errors with large logs:**
- Process logs in chunks
- Increase PHP memory limit: `ini_set('memory_limit', '512M');`

**IPv6 CIDR expansion fails:**
- Install `php-gmp` extension
- Verify GMP is enabled: `php -m | grep gmp`

## ⚠️ Disclaimer

This tool is provided for legitimate security monitoring purposes only. Users are responsible for:
- Ensuring compliance with applicable laws and regulations
- Reviewing detected IPs before taking blocking action
- Maintaining appropriate access controls
- Regular auditing of blocked IP lists

Use at your own risk. The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

MIT License - Use and modify freely.
