package org.apache.shiro.aspectj;

import java.lang.reflect.Method;

import org.apache.shiro.aop.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.AdviceSignature;
import org.aspectj.lang.reflect.MethodSignature;

/**
 * Helper class that adapts and aspectj {@link JoinPoint}.
 * 
 * @author J-C Desrochers
 * @since 1.0.0
 */
public class BeforeAdviceMethodInvocationAdapter implements MethodInvocation {

  private Method _method;
  private Object[] _arguments;

  /**
   * Factory method that creates a new {@link BeforeAdviceMethodInvocationAdapter} instance
   * using the AspectJ {@link JoinPoint} provided. The the joint point passed in is not
   * a method joint point, this method throws an {@link IllegalArgumentException}.
   * 
   * @param aJoinPoint The AspectJ {@link JoinPoint} to use to adapt the advice.
   * @return The created instance.
   * @throws IllegalArgumentException If the join point passed in does not involve a method call.
   */
  public static BeforeAdviceMethodInvocationAdapter createFrom(JoinPoint aJoinPoint) {
    if (aJoinPoint.getSignature() instanceof MethodSignature) {
      return new BeforeAdviceMethodInvocationAdapter(
              ((MethodSignature) aJoinPoint.getSignature()).getMethod(),
              aJoinPoint.getArgs());
      
    } else if (aJoinPoint.getSignature() instanceof AdviceSignature) {
      return new BeforeAdviceMethodInvocationAdapter(
              ((AdviceSignature) aJoinPoint.getSignature()).getAdvice(),
              aJoinPoint.getArgs());
      
    } else {
      throw new IllegalArgumentException("The joint point signature is invalid: expected a MethodSignature or an AdviceSignature but was " + aJoinPoint.getSignature());
    }
  }
  
  /**
   * Creates a new {@link BeforeAdviceMethodInvocationAdapter} instance.
   *
   * @param aMethod The method to invoke.
   * @param someArguments The arguments of the method invocation.
   */
  public BeforeAdviceMethodInvocationAdapter(Method aMethod, Object[] someArguments) {
    _method = aMethod;
    _arguments = someArguments;
  }
  
  /* (non-Javadoc)
   * @see org.apache.shiro.aop.MethodInvocation#getArguments()
   */
  public Object[] getArguments() {
    return _arguments;
  }

  /* (non-Javadoc)
   * @see org.apache.shiro.aop.MethodInvocation#getMethod()
   */
  public Method getMethod() {
    return _method;
  }

  /* (non-Javadoc)
   * @see org.apache.shiro.aop.MethodInvocation#proceed()
   */
  public Object proceed() throws Throwable {
    // Do nothing since this adapts a before advice
    return null;
  }
}
