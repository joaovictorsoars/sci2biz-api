# Generated by Django 5.1.1 on 2024-10-07 12:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sci2biz_app', '0003_users_groups_users_is_staff_users_is_superuser_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='users',
            old_name='user_id',
            new_name='id',
        ),
    ]