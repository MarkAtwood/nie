use axum::{http::header, response::IntoResponse};

const INDEX_HTML: &str = include_str!("../web/index.html");

pub async fn handle_index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_html_no_external_resources() {
        // Verify no CDN URLs in the HTML
        assert!(
            !INDEX_HTML.contains("https://cdn."),
            "index.html must not reference CDN resources"
        );
        assert!(
            !INDEX_HTML.contains("https://unpkg."),
            "index.html must not reference unpkg"
        );
        assert!(
            !INDEX_HTML.contains("https://cdnjs."),
            "index.html must not reference cdnjs"
        );
    }

    #[test]
    fn test_index_html_has_required_elements() {
        assert!(
            INDEX_HTML.contains("id=\"messages\""),
            "must have messages div"
        );
        assert!(
            INDEX_HTML.contains("id=\"msg-input\""),
            "must have msg-input"
        );
        assert!(
            INDEX_HTML.contains("id=\"users-list\""),
            "must have users-list"
        );
        assert!(
            INDEX_HTML.contains("/ws/events"),
            "must reference /ws/events"
        );
        assert!(
            INDEX_HTML.contains("/api/whoami"),
            "must reference /api/whoami"
        );
        assert!(INDEX_HTML.contains("/api/send"), "must reference /api/send");
    }
}
