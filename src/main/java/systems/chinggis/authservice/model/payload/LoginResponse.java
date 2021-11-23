package systems.chinggis.authservice.model.payload;

import lombok.Data;

@Data
public class LoginResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String email;
}
