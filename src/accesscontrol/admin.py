
from django.contrib import admin


class AccessControlEditAdmin(admin.ModelAdmin):
    list_editable = ('__str__', 'entity', 'perm', 'resource')
    list_display = ('__str__', 'entity', 'perm', 'resource')
    actions = ('action1', )

    def action1(self):
        pass

