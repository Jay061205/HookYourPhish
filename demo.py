import streamlit as st

# Initialize state if not already done
if "show_modal" not in st.session_state:
    st.session_state.show_modal = False

# Display info icon and handle click
col1, col2 = st.columns([1, 10])
with col1:
    if st.button("ⓘ", key="info_icon"):
        st.session_state.show_modal = True

with col2:
    uploaded_files = st.file_uploader(
        "📤 Upload one or more `.eml` files",
        type=["eml"],
        accept_multiple_files=True,
        label_visibility="visible"
    )

# Simulated modal using conditional rendering
if st.session_state.show_modal:
    with st.container():
        st.markdown("---")
        st.subheader("📽️ How to Download `.eml` Files")
        st.video("path_to_your_video.mp4")  # Replace with actual video path or URL
        if st.button("Close"):
            st.session_state.show_modal = False
        st.markdown("---")



            # components.html(
            # """
            # <style>
            # /* The Modal (background) */
            # .modal {
            # display: none;
            # position: fixed;
            # z-index: 1000;
            # left: 0;
            # top: 0;
            # width: 100%;
            # height: 100%;
            # overflow: auto;
            # background-color: rgba(0,0,0,0.4);
            # }

            # /* Modal Content */
            # .modal-content {
            # background-color: #fefefe;
            # margin: 10% auto;
            # padding: 20px;
            # border: 1px solid #888;
            # width: 80%;
            # max-width: 600px;
            # border-radius: 10px;
            # }

            # .close {
            # color: #aaa;
            # float: right;
            # font-size: 28px;
            # font-weight: bold;
            # cursor: pointer;
            # }

            # .info-button {
            # background-color: transparent;
            # border: none;
            # font-size: 24px;
            # color: #2c87f0;
            # cursor: pointer;
            # }

            # .info-button:hover {
            # color: #1a6ed1;
            # }
            # </style>

            # <button class="info-button" onclick="document.getElementById('myModal').style.display='block'">ℹ️</button>

            # <div id="myModal" class="modal">
            # <div class="modal-content">
            #     <span class="close" onclick="document.getElementById('myModal').style.display='none'">&times;</span>
            #     <h3>How to Download .eml Files</h3>
            #     <p>Watch the tutorial below:</p>
            #     <iframe width="100%" height="315" src="https://www.youtube.com/embed/YOUR_VIDEO_ID" 
            #     title="Tutorial Video" frameborder="0" allowfullscreen></iframe>
            # </div>
            # </div>

            # <script>
            # // Close modal when clicking outside the content
            # window.onclick = function(event) {
            # var modal = document.getElementById('myModal');
            # if (event.target == modal) {
            #     modal.style.display = "none";
            # }
            # }
            # </script>
            # """,
            # height=500,
            # ),