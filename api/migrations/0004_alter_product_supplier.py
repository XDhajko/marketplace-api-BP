# Generated by Django 5.1.6 on 2025-02-25 16:15

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_alter_product_supplier'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='supplier',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='products', to='api.supplier'),
        ),
    ]
