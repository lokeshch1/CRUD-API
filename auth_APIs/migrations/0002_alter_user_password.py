# Generated by Django 4.1 on 2022-08-23 09:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_APIs', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
