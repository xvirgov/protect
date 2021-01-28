package com.ibm.pross.client.app.http.handlers;

import com.ibm.pross.common.exceptions.http.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("restriction")
public abstract class BaseHttpHandler implements HttpHandler {

    @Override
    public void handle(final HttpExchange exchange) throws IOException {
        // Invoke the sub-class's handler
        try {
            this.handleWithExceptions(exchange);
        } catch (final HttpException e) {
            final String response = e.getErrorCode() + ": " + e.getErrorMessage() + "\n";
            final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(e.getErrorCode(), binaryResponse.length);
            try (final OutputStream os = exchange.getResponseBody();) {
                os.write(binaryResponse);
            }
        } catch (final Throwable e) {
            // Treat as an internal exception (but include stack trace for debugging)
            final StringWriter writer = new StringWriter();
            e.printStackTrace(new PrintWriter(writer));
            final String stackTrace = writer.toString();

            final String response = "500: Internal Error\n" + stackTrace;
            final byte[] binaryResponse = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(HttpStatusCode.NOT_AUTHORIZED, binaryResponse.length);
            try (final OutputStream os = exchange.getResponseBody();) {
                os.write(binaryResponse);
            }
        }
    }

    /**
     * This method catches any exception that might be thrown and returns an
     * appropriate HTTP status code and error message.
     *
     * @see HttpStatusCode
     *
     * @param exchange
     * @throws IOException
     * @throws UnauthorizedException
     * @throws NotFoundException
     * @throws BadRequestException
     * @throws ResourceUnavailableException
     * @throws InternalServerException
     */
    public abstract void handleWithExceptions(final HttpExchange exchange)
            throws IOException, UnauthorizedException, NotFoundException, ConflictException, BadRequestException, ResourceUnavailableException, InternalServerException;
}
