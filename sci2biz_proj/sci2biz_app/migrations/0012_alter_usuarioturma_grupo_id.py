# Generated by Django 5.1.1 on 2024-12-02 18:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sci2biz_app', '0011_remove_turma_monitor_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usuarioturma',
            name='grupo_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='sci2biz_app.grupoturmas'),
        ),
    ]
