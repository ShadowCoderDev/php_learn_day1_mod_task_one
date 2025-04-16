<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

/**
 * @OA\Info(
 *     title="سیستم احراز هویت API",
 *     version="1.0.0",
 *     description="نقاط پایانی API برای مدیریت و احراز هویت کاربران",
 *     @OA\Contact(
 *         email="admin@example.com",
 *         name="پشتیبانی API"
 *     ),
 *     @OA\License(
 *         name="Apache 2.0",
 *         url="http://www.apache.org/licenses/LICENSE-2.0.html"
 *     )
 * )
 * @OA\Server(
 *     url=L5_SWAGGER_CONST_HOST,
 *     description="سرور API"
 * )
 * @OA\SecurityScheme(
 *     securityScheme="bearerAuth",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="Sanctum"
 * )
 */
class ApiController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/register",
     *     summary="ثبت نام کاربر جدید",
     *     description="ایجاد حساب کاربری جدید با اطلاعات ارائه شده",
     *     operationId="registerUser",
     *     tags={"احراز هویت"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="اطلاعات ثبت نام کاربر",
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="محمد حسن"),
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="Password123"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="Password123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="کاربر با موفقیت ثبت نام شد",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User registered successfully"),
     *             @OA\Property(property="user", type="object"),
     *             @OA\Property(property="token", type="string", example="1|laravel_sanctum_G2LPVKHoxrFvyKzOGiDIm9aNPBnpTWBTkF8QCKkl")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="خطای اعتبارسنجی",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="خطای سرور",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="خطا در ثبت نام کاربر")
     *         )
     *     )
     * )
     */
    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation error',
                'errors' => $validator->errors()
            ], 422);
        }
        
        // create user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        // create token
        $token = $user->createToken('auth_token')->plainTextToken;
        // return response
        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token,
        ], 201);
    }

    /**
     * @OA\Post(
     *     path="/api/login",
     *     summary="ورود کاربر",
     *     description="احراز هویت کاربر و ارائه توکن دسترسی",
     *     operationId="loginUser",
     *     tags={"احراز هویت"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="اطلاعات ورود کاربر",
     *         @OA\JsonContent(
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="Password123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="ورود موفقیت‌آمیز",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User logged in successfully"),
     *             @OA\Property(property="user", type="object"),
     *             @OA\Property(property="token", type="string", example="1|laravel_sanctum_CKoz8YJkPdRBMiWIQFA7NK1oGxLIv5mz9j9BkWmO")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="ورود ناموفق",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="خطای اعتبارسنجی",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="خطای سرور",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="خطا در ورود به سیستم")
     *         )
     *     )
     * )
     */
    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation error',
                'errors' => $validator->errors()
            ], 422);
        }
        
        // check user
        $user = User::where('email', $request->email)->first();
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }
        // create token
        $token = $user->createToken('auth_token')->plainTextToken;
        // return response
        return response()->json([
            'message' => 'User logged in successfully',
            'user' => $user,
            'token' => $token,
        ], 200);
    }

    /**
     * @OA\Get(
     *     path="/api/logout",
     *     summary="خروج کاربر",
     *     description="لغو توکن دسترسی کاربر",
     *     operationId="logoutUser",
     *     tags={"احراز هویت"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="خروج موفقیت‌آمیز",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User logged out successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="خطای احراز هویت",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="خطای سرور",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="خطا در خروج از سیستم")
     *         )
     *     )
     * )
     */
    public function logout(Request $request){
        // revoke token
        $request->user()->currentAccessToken()->delete();
        // return response
        return response()->json([
            'message' => 'User logged out successfully',
        ], 200);
    }

    /**
     * @OA\Get(
     *     path="/api/profile",
     *     summary="دریافت پروفایل کاربر",
     *     description="اطلاعات پروفایل کاربر احراز هویت شده را برمی‌گرداند",
     *     operationId="getUserProfile",
     *     tags={"کاربر"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="دریافت موفقیت‌آمیز پروفایل",
     *         @OA\JsonContent(
     *             @OA\Property(property="user", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="خطای احراز هویت",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="خطای سرور",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="خطا در دریافت پروفایل")
     *         )
     *     )
     * )
     */
    public function profile(Request $request){
        // return response
        return response()->json([
            'user' => $request->user(),
        ], 200);
    }

    /**
     * @OA\Get(
     *     path="/api/refresh-token",
     *     summary="تازه‌سازی توکن دسترسی",
     *     description="صدور یک توکن دسترسی جدید برای کاربر احراز هویت شده",
     *     operationId="refreshToken",
     *     tags={"احراز هویت"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="تازه‌سازی موفقیت‌آمیز توکن",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Token refreshed successfully"),
     *             @OA\Property(property="token", type="string", example="1|laravel_sanctum_CKoz8YJkPdRBMiWIQFA7NK1oGxLIv5mz9j9BkWmO")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="خطای احراز هویت",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="خطای سرور",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="خطا در تازه‌سازی توکن")
     *         )
     *     )
     * )
     */
    public function refreshToken(Request $request){
        // revoke token
        $request->user()->currentAccessToken()->delete();
        // create new token
        $token = $request->user()->createToken('auth_token')->plainTextToken;
        // return response
        return response()->json([
            'message' => 'Token refreshed successfully',
            'token' => $token,
        ], 200);
    }

    public function __construct()
    {
        $this->middleware('auth:sanctum')->except(['register', 'login']);
    }
}