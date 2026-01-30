import os
from pathlib import Path
from dotenv import load_dotenv

# 1. Load Environment Variables
# Pastikan file .env ada di folder root proyek
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(os.path.join(BASE_DIR, '.env'))

# 2. Security Configuration
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# 3. Application Definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # App milikmu
    'dashboard',
    'snort',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware', # Untuk melayani CSS di Gunicorn
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# 4. Database Configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# 5. Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# 6. Internationalization
LANGUAGE_CODE = 'id-id'
TIME_ZONE = 'Asia/Jakarta'
USE_I18N = True
USE_TZ = True

# 7. Static Files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
# Menggunakan Whitenoise untuk kompresi file statis
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# 8. Default Primary Key Field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 9. Snort Integration Paths (Custom)
SNORT_RULES_DIR = os.getenv('SNORT_RULES_DIR', '/usr/local/etc/snort/rules')
SNORT_IP_WHITELIST_PATH = os.getenv('SNORT_IP_WHITELIST_PATH', '/usr/local/etc/snort/whitelist.txt')
SNORT_IP_BLOCKLIST_PATH = os.getenv('SNORT_IP_BLOCKLIST_PATH', '/usr/local/etc/snort/blocklist.txt')

SNORT_LOG_JSON_PATH = os.getenv('SNORT_LOG_JSON_PATH', '/var/log/snort/alert_json.txt')
SNORT_LOG_FAST_PATH = os.getenv('SNORT_LOG_FAST_PATH', '/var/log/snort/alert_fast.txt')
SNORT_LOG_PATH = SNORT_LOG_JSON_PATH
SNORT_DASHBOARD_LOG_PATH = SNORT_LOG_FAST_PATH


LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'