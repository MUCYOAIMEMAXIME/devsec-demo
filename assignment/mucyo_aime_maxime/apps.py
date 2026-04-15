from django.apps import AppConfig


class MucyoAimeMaximeConfig(AppConfig):
    name = 'mucyo_aime_maxime'
    verbose_name = 'UAS - User Authentication Service'
    
    def ready(self):
        """Initialize default groups and signals on app startup."""
        import sys
        if 'manage.py' in sys.argv and ('runserver' in sys.argv or 'migrate' in sys.argv):
            from .admin import create_default_groups
            create_default_groups()
        from . import signals  # Import signals to register receivers
