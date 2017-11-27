package org.jscep.transport;


/**
 * This class provides a generic callback accepting either a result object or
 * an error. As it has just one method, it follows SAM convention and can be
 * implemented as a lambda on Java 8 and higher.
 * <p>
 * <code>null</code> is allowed for the result even when error is
 * <code>null</code> too - in particular in case of
 * <code>ResultHandler<Void></code>, which becomes just a completion callback.
 * So, an idiom for the result handler is to check the error for
 * <code>null</code> first and then handle the result.
 *
 * @param <T> type of the result
 */
public interface ResultHandler<T> {
    void handle(T t, Throwable e);
}