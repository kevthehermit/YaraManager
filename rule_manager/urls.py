from django.conf.urls import patterns, url

from rule_manager import views

urlpatterns = patterns('',
    # Index
    url(r'^$', views.index_view, name='index'),
    
    # Login Page
    url(r'^login/', views.login_page, name='login'),
    
    # Logout Page
    url(r'^logout/', views.logout_page, name='logout'),
    
    # Rule Pages
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule_view'),

    # Search
    url(r'^search/', views.search, name='search'),
    
    # Post Data Pages
    url(r'^update/(?P<add_type>.+)/$', views.post_data, name='post_data'), 

    # Disable / enable  rule
    url(r'^disable/(?P<rule_id>\d+)/$', views.disable_rule, name='disable'), 
    url(r'^enable/(?P<rule_id>\d+)/$', views.enable_rule, name='enable'), 

    # Disable / enable  rule
    url(r'^addtag/(?P<rule_id>\d+)/(?P<cat_name>.+)$', views.addtag, name='addtag'), 
    url(r'^deltag/(?P<rule_id>\d+)/(?P<cat_name>.+)$', views.deltag, name='deltag'), 

    # Export Rules
    # Single
    url(r'^export/rule/(?P<rule_id>\d+)/$', views.export_rule, name='export_rule'),
    # By Category
    url(r'^export/category/(?P<cat_name>.+)/$', views.export_cat, name='export_cat'),
)
