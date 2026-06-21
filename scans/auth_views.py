from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView


class UserLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True


class UserLogoutView(LogoutView):
    next_page = "scans:index"


class RegisterView(CreateView):
    form_class = UserCreationForm
    template_name = "registration/register.html"
    success_url = reverse_lazy("scans:index")

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect(self.success_url)
