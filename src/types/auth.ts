export interface SignupRequest {
  email: string;
  password: string;
  passwordRepetition: string;
  firstName: string;
  lastName: string;
}

export interface SigninRequest {
  email: string;
  password: string;
}

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  passwordHash: string;
  createdAt: Date;
}

export interface AuthResponse {
  user: Omit<User, 'passwordHash'>;
}

export interface ValidationError {
  field: string;
  message: string;
}
