package ncryptf;

public class TestCase
{
    public String httpMethod;
    public String uri;
    public String payload;

    public TestCase(String httpMethod, String uri, String payload)
    {
        this.httpMethod = httpMethod;
        this.uri = uri;
        this.payload = payload;
    }
}