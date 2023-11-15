## About Laravel/Next API

This is laravel api designed to be used with NextJS 13. This utilizes laravel sanctum for token based authentication.

Laravel is accessible, powerful, and provides tools required for large, robust applications.

## Getting Started

First clone the project:

```bash
git clone https://github.com/charlesCaballero/laravel-next-api.git
```

Go inside your project folder then install all dependencies:

```bash
cd laravel-next-api
composer install
```

Make a copy of `.env.example` file then rename the copy to `.env`. <br>
Set-up database connections in the `.env` file:

```bash
php artisan migrate
```

## Customizing authentication

You can start customizing authentication api by changing the credentials in the `login` function of `App\Http\Controllers\AuthController`.<br>
You may also change the columns in the `register` function of `App\Http\Controllers\AuthController` depending on your needs.
