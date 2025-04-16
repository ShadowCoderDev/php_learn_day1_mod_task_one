<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ApiController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// API Authentication Routes
Route::post('/register', [ApiController::class, 'register']);
Route::post('/login', [ApiController::class, 'login']);
Route::get('/logout', [ApiController::class, 'logout'])->middleware('auth:sanctum');
Route::get('/profile', [ApiController::class, 'profile'])->middleware('auth:sanctum');
Route::get('/refresh-token', [ApiController::class, 'refreshToken'])->middleware('auth:sanctum');
