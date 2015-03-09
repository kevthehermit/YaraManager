from django.contrib import admin
from rule_manager.models import Rule, MetaData, RuleStrings, Condition


admin.site.register(Rule)
admin.site.register(MetaData)
admin.site.register(RuleStrings)
admin.site.register(Condition)
