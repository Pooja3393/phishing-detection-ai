import cv2


def decode_qr(image_path):
    """
    Decode a QR code from an image using OpenCV.
    """

    image = cv2.imread(image_path)

    if image is None:
        return None, "Could not read the image."

    detector = cv2.QRCodeDetector()

    data, points, _ = detector.detectAndDecode(image)

    if data:
        return data, None

    return None, "No readable QR code detected."


if __name__ == "__main__":

    image_path = input("Enter QR image path: ")

    data, error = decode_qr(image_path)

    if error:
        print("❌", error)

    else:
        print("=" * 50)
        print("QR CODE DETECTED")
        print("=" * 50)
        print("Extracted Data:")
        print(data)