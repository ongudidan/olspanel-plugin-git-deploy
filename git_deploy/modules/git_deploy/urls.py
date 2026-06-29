from django.urls import path
from . import views

urlpatterns = [
    path('gui/', views.gui_view, name='git_deploy_gui'),
    path('webhook/', views.webhook_view, name='git_deploy_webhook'),
    path('create/', views.create_deployment_view, name='git_deploy_create'),
    path('delete/<int:dep_id>/', views.delete_deployment_view, name='git_deploy_delete'),
    path('logs/<int:dep_id>/', views.get_logs_view, name='git_deploy_logs'),
    path('deploy/<int:dep_id>/', views.trigger_manual_deploy_view, name='git_deploy_trigger'),
    path('deploy/stream/<int:log_id>/', views.log_stream_view, name='git_deploy_log_stream'),
    path('token/', views.manage_token_view, name='git_deploy_token'),
    path('repos/', views.fetch_github_repos_view, name='git_deploy_repos'),
    path('settings/', views.manage_settings_view, name='git_deploy_settings'),
    path('settings/disconnect/', views.disconnect_github_view, name='git_deploy_settings_disconnect'),
    path('oauth/redirect/', views.oauth_redirect_view, name='git_deploy_oauth_redirect'),
    path('oauth/callback/', views.oauth_callback_view, name='git_deploy_oauth_callback'),
    path('app/callback/', views.app_manifest_callback_view, name='git_deploy_app_callback'),
]
