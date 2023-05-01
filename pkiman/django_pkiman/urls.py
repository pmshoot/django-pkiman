from django.urls import path

from django_pkiman import views

app_name = 'pkiman'

urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('management/', views.ManagementView.as_view(), name='management'),
    path('reestr/', views.ManagementReestrView.as_view(), name='reestr'),
    path('crl/<str:pk>/update/', views.ManagementUpdateCrl.as_view(), name='update_crl'),
    path('crt/<str:pk>/parent/get/', views.ManagementGetParentCrt.as_view(), name='get_parent_crt'),
    path('uploads/', views.ManagementUploadsView.as_view(), name='uploads'),
    path('schedule/', views.ManagementScheduleView.as_view(), name='schedule'),
    path('journal/', views.ManagementJournalView.as_view(), name='journal'),
    path('docs/', views.DocsView.as_view(), name='docs'),
]
