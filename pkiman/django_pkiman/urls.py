from django.urls import include, path

from django_pkiman import views

app_name = 'pkiman'

mgmt_urls = [
    path('crl/<str:pk>/update/', views.ManagementUpdateCrl.as_view(), name='update_crl'),
    path('crt/<str:pk>/parent/get/', views.ManagementGetParentCrt.as_view(), name='get_parent_crt'),
    path('uploads/', views.ManagementUploadsView.as_view(), name='uploads'),
    path('indexing/', views.ManagementUrlIndexView.as_view(), name='url_index_file'),
    path('schedule/', views.ManagementScheduleView.as_view(), name='schedule'),
    path('journal/', views.ManagementJournalView.as_view(), name='journal'),
    ]

urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('mgmt/', include(mgmt_urls)),
    path('docs/', views.DocsView.as_view(), name='docs'),
]
