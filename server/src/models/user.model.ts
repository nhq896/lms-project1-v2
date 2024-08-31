import mongoose, { Document } from "mongoose";
import * as bcrypt from "bcryptjs";

const emailRegexPattern: RegExp = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  avatar: string;
  role: string;
  isVerified: boolean;
  courses: Array<{ courseId: string }>;
  comparePassword: (password: string) => Promise<boolean>;
}

const userSchema = new mongoose.Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "Vui lòng nhập tên của bạn!"],
    },
    email: {
      type: String,
      required: [true, "Vui lòng nhập địa chỉ email!"],
      validate: {
        validator: (value: string) => emailRegexPattern.test(value),
        message: "Vui lòng nhập một địa chỉ email hợp lệ!",
      },
      unique: true,
    },
    password: {
      type: String,
      required: [true, "Vui lòng nhập mặt khẩu!"],
      minlength: [6, "Mật khẩu cần có ít nhất 6 ký tự!"],
      select: false,
    },
    avatar: {
      type: String,
    },
    role: {
      type: String,
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    courses: [
      {
        courseId: String,
      },
    ],
  },
  { timestamps: true }
);

// dùng để hash mật khẩu trước khi lưu vào db
userSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// phương thức so sánh mật khẩu khi đăng nhập
userSchema.methods.comparePassword = async function (
  enteredPassword: string
): Promise<Boolean> {
  return await bcrypt.compare(enteredPassword, this.password);
};

const userModel = mongoose.model<IUser>("User", userSchema);

export default userModel;
