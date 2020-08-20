<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('login', 'apiAuth\AuthController@login')->name('login');
Route::post('register', 'apiAuth\AuthController@register')->name('register');
Route::group(['middleware' => 'auth:api'], function(){
    Route::get('emailValidation/{email}', 'apiAuth\AuthController@emailValidation')->name('emailValidation');
});