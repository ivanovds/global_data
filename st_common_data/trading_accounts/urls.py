from django.urls import path

from st_common_data.trading_accounts.views import UpdateFomAccManView

urlpatterns = [
    path('acc_man/updates/', UpdateFomAccManView.as_view(), name='acc_man_sub'),
]
