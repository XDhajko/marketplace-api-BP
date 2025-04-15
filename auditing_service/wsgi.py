import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')  # use your main settings
os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', 'true')  # optional, for some async-safe warnings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
os.environ.setdefault('DJANGO_ROOT_URLCONF', 'auditing_service.root_urls')  # THIS IS IMPORTANT

application = get_wsgi_application()
