import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { User, SignupRequest, SigninRequest, AuthResponse } from '../types/auth';

const users: User[] = [];

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = (process.env.JWT_EXPIRES_IN || '24h') as string;

export class AuthService {
  async signup(userData: SignupRequest): Promise<{ user: Omit<User, 'passwordHash'>, token: string }> {
    // Check if user already exists
    const existingUser = users.find(user => user.email === userData.email);
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(userData.password, saltRounds);

    // Create new user
    const newUser: User = {
      id: uuidv4(),
      email: userData.email,
      firstName: userData.firstName,
      lastName: userData.lastName,
      passwordHash,
      createdAt: new Date()
    };

    users.push(newUser);

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN as any }
    );

    // Return user data (without password) and token for cookie setting
    const { passwordHash: _, ...userWithoutPassword } = newUser;
    return {
      user: userWithoutPassword,
      token
    };
  }

  async signin(credentials: SigninRequest): Promise<{ user: Omit<User, 'passwordHash'>, token: string }> {
    // Find user by email
    const user = users.find(u => u.email === credentials.email);
    if (!user) {
      throw new Error('Invalid email or password');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(credentials.password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error('Invalid email or password');
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN as any }
    );

    // Return user data (without password) and token for cookie setting
    const { passwordHash: _, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      token
    };
  }

  async getUserById(userId: string): Promise<Omit<User, 'passwordHash'> | null> {
    const user = users.find(u => u.id === userId);
    if (!user) {
      return null;
    }

    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }
}
