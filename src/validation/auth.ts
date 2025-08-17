import Joi from 'joi';
import { SignupRequest, SigninRequest } from '../types/auth';

export const signupSchema = Joi.object<SignupRequest>({
  email: Joi.string().email().required().messages({
    'string.email': 'Email must be a valid email address',
    'any.required': 'Email is required'
  }),
  password: Joi.string().min(8).required().messages({
    'string.min': 'Password must be at least 8 characters long',
    'any.required': 'Password is required'
  }),
  passwordRepetition: Joi.string().valid(Joi.ref('password')).required().messages({
    'any.only': 'Password repetition must match password',
    'any.required': 'Password repetition is required'
  }),
  firstName: Joi.string().min(2).max(50).required().messages({
    'string.min': 'First name must be at least 2 characters long',
    'string.max': 'First name must be at most 50 characters long',
    'any.required': 'First name is required'
  }),
  lastName: Joi.string().min(2).max(50).required().messages({
    'string.min': 'Last name must be at least 2 characters long',
    'string.max': 'Last name must be at most 50 characters long',
    'any.required': 'Last name is required'
  })
});

export const signinSchema = Joi.object<SigninRequest>({
  email: Joi.string().email().required().messages({
    'string.email': 'Email must be a valid email address',
    'any.required': 'Email is required'
  }),
  password: Joi.string().required().messages({
    'any.required': 'Password is required'
  })
});
