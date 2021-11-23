package systems.chinggis.authservice.model.payload;

import lombok.Data;

import java.util.List;

@Data
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String username;
    private String email;
}
