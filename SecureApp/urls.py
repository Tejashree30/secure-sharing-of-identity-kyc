from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
			path("AdminLogin.html", views.AdminLogin, name="AdminLogin"),
			path("AdminLoginAction", views.AdminLoginAction, name="AdminLoginAction"),
			path("UserLogin.html", views.UserLogin, name="UserLogin"),
			path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
			path("Register.html", views.Register, name="Register"),
			path("RegisterAction", views.RegisterAction, name="RegisterAction"),
			path("UploadKYC.html", views.UploadKYC, name="UploadKYC"),
			path("UploadKYCAction", views.UploadKYCAction, name="UploadKYCAction"),
			path("ViewKYC", views.ViewKYC, name="ViewKYC"),
			path("UpdateKYCAction", views.UpdateKYCAction, name="UpdateKYCAction"),
			path("CheckStatus", views.CheckStatus, name="CheckStatus"),
			path("AccessKYC.html", views.AccessKYC, name="AccessKYC"),
			path("AccessKYCAction", views.AccessKYCAction, name="AccessKYCAction"),
]