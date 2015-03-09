from django.conf.urls import patterns, include, url
from django.contrib import admin

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'YaraManager.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^', include('rule_manager.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
