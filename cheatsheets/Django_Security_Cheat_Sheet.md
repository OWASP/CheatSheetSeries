# Django Security Cheat Sheet

## Introduction

The Django framework is a powerful Python web framework, and it comes with built-in security features that can be used out-of-the-box to prevent common web vulnerabilities. This cheat sheet lists actions and security tips developers can take to develop secure Django applications. It aims to cover common vulnerabilities to increase the security posture of your Django application. Each item has a brief explanation and relevant code samples that are specific to the Django environment.

The Django framework provides some built-in security features that aim to be secure-by-default. These features are also flexible to empower a developer to re-use components for complex use-cases. This opens up scenarios where developers unfamiliar with the inner workings of the components can configure them in an insecure way. This cheat sheet aims to enumerate some such use cases.

## General Recommendations

- Always keep Django and your application's dependencies up-to-date to keep up with security vulnerabilities.
- Ensure that the application is never in `DEBUG` mode in a production environment. Never run `DEBUG = True` in production.
- Use packages like [`django_ratelimit`](https://django-ratelimit.readthedocs.io/en/stable/) or [`django-axes`](https://django-axes.readthedocs.io/en/latest/index.html) to prevent brute-force attacks.

## Authentication

- Use `django.contrib.auth` app for views and forms for user authentication operations such as login, logout, password change, etc. Include the module and its dependencies `django.contrib.contenttypes` and `django.contrib.sessions` in the `INSTALLED_APPS` setting in the `settings.py` file.

  ```python
  INSTALLED_APPS = [
      # ...
      'django.contrib.auth',
      'django.contrib.contenttypes',
      'django.contrib.sessions',
      # ...
  ]
  ```

- Use the `@login_required` decorator to ensure that only authenticated users can access a view. The sample code below illustrates usage of `@login_required`.

  ```python
  from django.contrib.auth.decorators import login_required

  # User is redirected to default login page if not authenticated.
  @login_required
  def my_view(request):
    # Your view logic

  # User is redirected to custom '/login-page/' if not authenticated.
  @login_required(login_url='/login-page/')
  def my_view(request):
    # Your view logic
  ```

- Use password validators for enforcing password policies. Add or update the `AUTH_PASSWORD_VALIDATORS` setting in the `settings.py` file to include specific validators required by your application.

  ```python
  AUTH_PASSWORD_VALIDATORS = [
    {
      # Checks the similarity between the password and a set of attributes of the user.
      'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
      'OPTIONS': {
        'user_attributes': ('username', 'email', 'first_name', 'last_name'),
        'max_similarity': 0.7,
      }
    },
    {
      # Checks whether the password meets a minimum length.
      'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
      'OPTIONS': {
        'min_length': 8,
      }
    },
    {
      # Checks whether the password occurs in a list of common passwords
      'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
      # Checks whether the password isn’t entirely numeric
      'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    }
  ]
  ```

- Store passwords using `make-password` utility function to hash a plain-text password.

  ```python
  from django.contrib.auth.hashers import make_password
  #...
  hashed_pwd = make_password('plaintext_password')
  ```

- Check a plaintext password against a hashed password by using the  `check-password` utility function.

  ```python
  from django.contrib.auth.hashers import check_password
  #...
  plain_pwd = 'plaintext_password'
  hashed_pwd = 'hashed_password_from_database'

  if check_password(plain_pwd, hashed_pwd):
    print("The password is correct.")
  else:
    print("The password is incorrect.")
  ```

## Key Management

The `SECRET_KEY` parameter in settings.py is used for cryptographic signing and should be kept confidential. Consider the following recommendations:

- Generate a key at least 50 characters or more, containing a mix of letters, digits, and symbols.
- Ensure that the `SECRET_KEY` is generated using a strong random generator, such as `get_random_secret_key()` function in Django.
- Avoid hard coding the `SECRET_KEY` value in settings.py or any other location. Consider storing the key-value in environment variables or secrets managers.

  ```python
  import os
  SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
  ```

- Regularly rotate the key, keeping in mind that this action can invalidate sessions, password reset tokens, etc. Rotate the key immediately it if it ever gets exposed.

## Headers

Include the `django.middleware.security.SecurityMiddleware` module in the `MIDDLEWARE` setting in your project's `settings.py` to add security-related headers to your responses. This module is used to set the following parameters:

- `SECURE_CONTENT_TYPE_NOSNIFF`: Set this key to `True`. Protects against MIME type sniffing attacks by enabling the header `X-Content-Type-Options: nosniff`.
- `SECURE_HSTS_SECONDS`: Ensures the site is only accessible via HTTPS.

Include the `django.middleware.clickjacking.XFrameOptionsMiddleware` module in the `MIDDLEWARE` setting in your project's `settings.py` (This module should be listed after the `django.middleware.security.SecurityMiddleware` module as ordering is important). This module is used to set the following parameters:

- `X_FRAME_OPTIONS`: Set this key to 'DENY' or 'SAMEORIGIN'. This setting adds the `X-Frame-Options` header to all HTTP responses. This protects against clickjacking attacks.

## Cookies

- `SESSION_COOKIE_SECURE`: Set this key to `True` in the `settings.py` file. This will send the session cookie over secure (HTTPS) connections only.
- `CSRF_COOKIE_SECURE`: Set this key to `True` in the `settings.py` file. This will ensure that the CSRF cookie is sent over secure connections only.
- Whenever you set a custom cookie in a view using the `HttpResponse.set_cookie()` method, make sure to set its secure parameter to `True`.

  ```python
  response = HttpResponse("Some response")
  response.set_cookie('my_cookie', 'cookie_value', secure=True)
  ```

## Cross Site Request Forgery (CSRF)

- Include the `django.middleware.csrf.CsrfViewMiddleware` module in the `MIDDLEWARE` setting in your project's `settings.py` to add CSRF related headers to your responses.
- In forms use the `{% csrf_token %}` template tag to include the CSRF token. A sample is shown below.

  ```html
  <form method="post">
      {% csrf_token %}
      <!-- Your form fields here -->
  </form>
  ```

- For AJAX calls, the CSRF token for the request has to be extracted prior to being used in the the AJAX call.  
- Additional recommendations and controls can be found at Django's [Cross Site Request Forgery protection](https://docs.djangoproject.com/en/5.2/ref/csrf/) documentation.

## Cross Site Scripting (XSS)

The recommendations in this section are in addition to XSS recommendations already mentioned previously.

- Use the built-in template system to render templates in Django. Refer to Django's [Automatic HTML escaping](https://docs.djangoproject.com/en/5.2/ref/templates/language/#automatic-html-escaping) documentation to learn more.
- Try to avoid using the `safe` filter (or `mark_safe` function) to disable Django's automatic template escaping. If you do need to use it, make sure the input is from a trusted source. Extra caution is required when handling user-controlled inputs.
- Use the [`json_script`](https://docs.djangoproject.com/en/5.2/ref/templates/builtins/#json-script) template filter for passing data to JavaScript in Django templates.
- Refer to Django's [Cross Site Scripting (XSS) protection](https://docs.djangoproject.com/en/5.2/topics/security/#cross-site-scripting-xss-protection) documentation to learn more.

## HTTPS

- Include the `django.middleware.security.SecurityMiddleware` module in the `MIDDLEWARE` setting in your project's `settings.py` if not already added.
- Set the `SECURE_SSL_REDIRECT = True` in the `settings.py` file to ensure that all communication is over HTTPS. This will redirect any HTTP requests automatically to HTTPS. This is also a 301 (permanent) redirect, so your browser will remember the redirect for subsequent requests.
- If your Django application is behind a proxy or load balancer, set the `SECURE_PROXY_SSL_HEADER` setting so that Django can detect the original request's protocol. For further details refer to [SECURE_PROXY_SSL_HEADER documentation](https://docs.djangoproject.com/en/5.2/ref/settings/#secure-proxy-ssl-header).

## Admin panel URL

It is advisable to modify the default URL leading to the admin panel (example.com/admin/), in order to slightly increase the difficulty for automated attacks. Here’s how to do it:

In the default app folder within your project, locate the `urls.py` file managing the top-level URLs. Within the file, modify the `urlpatterns` variable, a list, so that the URL leading to `admin.site.urls` is different from "admin/". This approach adds an extra layer of security by obscuring the common endpoint used for administrative access.

## Django's built-in command `check --deploy`

Django has built-in command [`check --deploy`](https://docs.djangoproject.com/en/stable/ref/django-admin/#cmdoption-check-deploy) for security checks. Example:

```
$ ./manage.py check --deploy
System check identified some issues:

WARNINGS:
?: (security.W004) You have not set a value for the SECURE_HSTS_SECONDS setting. If your entire site is served only over SSL, you may want to consider setting a value and enabling HTTP Strict Transport Security. Be sure to read the documentation first; enabling HSTS carelessly can cause serious, irreversible problems.
?: (security.W008) Your SECURE_SSL_REDIRECT setting is not set to True. Unless your site should be available over both SSL and non-SSL connections, you may want to either set this setting True or configure a load balancer or reverse-proxy server to redirect all connections to HTTPS.
?: (security.W009) Your SECRET_KEY has less than 50 characters, less than 5 unique characters, or it's prefixed with 'django-insecure-' indicating that it was generated automatically by Django. Please generate a long and random value, otherwise many of Django's security-critical features will be vulnerable to attack.
?: (security.W012) SESSION_COOKIE_SECURE is not set to True. Using a secure-only session cookie makes it more difficult for network traffic sniffers to hijack user sessions.
?: (security.W016) You have 'django.middleware.csrf.CsrfViewMiddleware' in your MIDDLEWARE, but you have not set CSRF_COOKIE_SECURE to True. Using a secure-only CSRF cookie makes it more difficult for network traffic sniffers to steal the CSRF token.
?: (security.W018) You should not have DEBUG set to True in deployment.
?: (security.W020) ALLOWED_HOSTS must not be empty in deployment.

System check identified 7 issues (0 silenced).

```

You can harden your Django project by addressing the warnings generated by this command.

## References

Additional documentation -

- [Clickjacking Protection](https://docs.djangoproject.com/en/5.2/topics/security/#clickjacking-protection)
- [Security Middleware](https://docs.djangoproject.com/en/5.2/ref/middleware/#module-django.middleware.security)
