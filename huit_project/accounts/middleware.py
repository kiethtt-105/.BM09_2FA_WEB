from django.shortcuts import redirect


class RoleMiddleware:

    def __init__(self,get_response):
        self.get_response=get_response

    def __call__(self,request):

        if request.path.startswith("/admin"):

            if request.user.is_authenticated:

                if not request.user.is_staff:
                    return redirect("dashboard")

        response=self.get_response(request)

        return response