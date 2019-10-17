# Introduction

This article propose a way to protect a file upload feature against submission of file containing malicious code.

# Context

Into web applications, when we expect upload of working documents from users, we can expose the application to submission of documents that we can categorize as *malicious*.

We use the term "malicious" here to refer to documents that embed *malicious code* that will be executed when another user (admin, back office operator...) will open the document with the associated application reader.

Usually, when an application expect his user to upload a document, the application expect to receive a document for which the intended use will be for reading/printing/archiving. The document should not alter is content at opening time and should be in a final rendered state.

The most common file types used to transmit *malicious code* into file upload feature are the following:

- Microsoft Office document: Word/Excel/PowerPoint using [VBA Macro](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications) and [OLE package](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding).
- Adobe PDF document: Insert malicious code as attachment.
- Images: Malicious code embedded into the file or use of binary file with image file extension.

# Approaches

Based on this context, the goals here are:

- For Word/Excel/PowerPoint/Pdf documents: Detect when a document contains "code"/OLE package, if it's the case then block the upload process.
- For Images document: Sanitize incoming image using re-writing approach and then disable/remove any "code" present (this approach also handle case in which the file sent is not an image).

Remarks:

- It's technically possible to perform sanitizing on Word/Excel/PowerPoint/PDF documents but we have chosen here the option to block them in order to avoid the risk of missing any evasion techniques and then let pass one evil document. The following [site](https://www.greyhathacker.net/?p=872) show how many way exists to embed Macro into a Microsoft Office documents.
- The other reason why we have chosen the blocking way is that for Word/Excel/PowerPoint, changing document format (for example by saving any document to `DOCX/XSLX/PPTX/PPSX` formats in order to be sure that no Macro can be executed) can have impacts or cause issues on document structure/rendering depending on the API used.

# Cases

## Common codes

The following codes are shared by the code snippets proposed into the rest of this article.

Interfaces:

*DocumentDetector*

``` java
import java.io.File;

/**
 * Interface to define detection methods.
 *
 */
public interface DocumentDetector {
    /**
     * Method to verify if the specified file contains a document that:<br>
     * <ul>
     * <li>Do not contains potential malicious content</li>
     * <li>Is part of the supported accepted format</li>
     * </ul>
     *
     * @param f File to validate
     *
     * @return TRUE only if the file fill the 2 rules above
     */
    boolean isSafe(File f);
}
```

*DocumentSanitizer*

``` java
import java.io.File;

/**
 * Interface to define sanitize methods.
 *
 */
public interface DocumentSanitizer {
    /**
     * Method to try to (sanitize) disable any code contained into the specified file 
     * by using re-writing approach.
     *
     * @param f File to made safe
     *
     * @return TRUE only if the specified file has been successfully made safe.
     */
    boolean madeSafe(File f);
}
```

## Case n°1: Word / Excel / PowerPoint

The reason why Aspose API have been used here are the following:

- There many way to embed Macro into a Microsoft Office document and, instead of manually support all the way that exists on the wild (they evolve every days), we prefer to use features from a company that perform R&D on these formats, precisely DOC/XLS/PPT native formats that are proprietary.
- The open source API POI for [DOC native format is limited](https://poi.apache.org/overview.html).
- The open source API JEXCELAPI for XLS native format is not often maintained (last publishing date from [2009](https://sourceforge.net/projects/jexcelapi/files/jexcelapi/)).

Detector for Word document:

``` java
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aspose.words.Document;
import com.aspose.words.FileFormatInfo;
import com.aspose.words.FileFormatUtil;
import com.aspose.words.NodeCollection;
import com.aspose.words.NodeType;
import com.aspose.words.Shape;

/**
 * Implementation of the detector for Microsoft Word document.
 *
 *
 */
public class WordDocumentDetectorImpl implements DocumentDetector {

    /** LOGGER */
    private static final Logger LOG = LoggerFactory.getLogger(WordDocumentDetectorImpl.class);

    /**
     * List of allowed Word format (WML = Word ML (Word 2003 XML)).<br>
     * Allow also DOCM because it can exists without macro inside.<br>
     * Allow also DOT/DOTM because both can exists without macro inside.<br>
     * We reject MHTML file because:<br>
     * <ul>
     * <li>API cannot detect macro into this format</li>
     * <li>Is not normal to use this format to represent a Word file 
     *     (there plenty of others supported format)</li>
     * </ul>
     */
    private static final List<String> ALLOWED_FORMAT = 
                         Arrays.asList(new String[] { "doc", "docx", "docm", "wml", "dot", "dotm" });

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("rawtypes")
    @Override
    public boolean isSafe(File f) {
        boolean safeState = false;
        try {
            if ((f != null) && f.exists() && f.canRead()) {
                // Perform a first check on Word document format
                FileFormatInfo formatInfo = FileFormatUtil.detectFileFormat(f.getAbsolutePath());
                String formatExtension = FileFormatUtil.loadFormatToExtension(formatInfo.getLoadFormat());
                if ((formatExtension != null) 
                && ALLOWED_FORMAT.contains(formatExtension.toLowerCase(Locale.US).replaceAll("\\.", ""))) {
                    // Load the file into the Word document parser
                    Document document = new Document(f.getAbsolutePath());
                    // Get safe state from Macro presence
                    safeState = !document.hasMacros();
                    // If document is safe then we pass to OLE objects analysis
                    if (safeState) {
                        // Get all shapes of the document
                        NodeCollection shapes = document.getChildNodes(NodeType.SHAPE, true);
                        Shape shape = null;
                        // Search OLE objects in all shapes
                        int totalOLEObjectCount = 0;
                        for (int i = 0; i < shapes.getCount(); i++) {
                            shape = (Shape) shapes.get(i);
                            // Check if the current shape has OLE object
                            if (shape.getOleFormat() != null) {
                                totalOLEObjectCount++;
                            }
                        }
                        // Update safe status flag according to number of OLE object found
                        if (totalOLEObjectCount != 0) {
                            safeState = false;
                        }

                    }
                }
            }
        }
        catch (Exception e) {
            safeState = false;
            LOG.warn("Error during Word file analysis !", e);
        }
        return safeState;
    }

}
```

Detector for Excel document:

``` java
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aspose.cells.FileFormatInfo;
import com.aspose.cells.FileFormatUtil;
import com.aspose.cells.MsoDrawingType;
import com.aspose.cells.OleObject;
import com.aspose.cells.Workbook;
import com.aspose.cells.Worksheet;

/**
 * Implementation of the detector for Microsoft Excel workbook.
 *
 *
 */
public class ExcelDocumentDetectorImpl implements DocumentDetector {

    /** LOGGER */
    private static final Logger LOG = LoggerFactory.getLogger(ExcelDocumentDetectorImpl.class);

    /**
     * List of allowed Excel format<br>
     * Allow also XLSM/XSLB because both can exists without macro inside.<br>
     * Allow also XLT/XLTM because both can exists without macro inside.<br>
     */
    private static final List<String> ALLOWED_FORMAT = 
                    Arrays.asList(new String[] { "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltm" });

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSafe(File f) {
        boolean safeState = false;
        try {
            if ((f != null) && f.exists() && f.canRead()) {
                // Perform a first check on Excel document format
                FileFormatInfo formatInfo = FileFormatUtil.detectFileFormat(f.getAbsolutePath());
                String formatExtension = FileFormatUtil.loadFormatToExtension(formatInfo.getLoadFormat());
                if ((formatExtension != null) 
                && ALLOWED_FORMAT.contains(formatExtension.toLowerCase(Locale.US).replaceAll("\\.", ""))) {
                    // Load the file into the Excel document parser
                    Workbook book = new Workbook(f.getAbsolutePath());
                    // Get safe state from Macro presence
                    safeState = !book.hasMacro();
                    // If document is safe then we pass to OLE objects analysis
                    if (safeState) {
                        // Search OLE objects in all workbook sheets
                        Worksheet sheet = null;
                        OleObject oleObject = null;
                        int totalOLEObjectCount = 0;
                        for (int i = 0; i < book.getWorksheets().getCount(); i++) {
                            sheet = book.getWorksheets().get(i);
                            for (int j = 0; j < sheet.getOleObjects().getCount(); j++) {
                                oleObject = sheet.getOleObjects().get(j);
                                if (oleObject.getMsoDrawingType() == MsoDrawingType.OLE_OBJECT) {
                                    totalOLEObjectCount++;
                                }
                            }
                        }
                        // Update safe status flag according to number of OLE object found
                        if (totalOLEObjectCount != 0) {
                            safeState = false;
                        }
                    }
                }
            }
        }
        catch (Exception e) {
            safeState = false;
            LOG.warn("Error during Excel file analysis !", e);
        }
        return safeState;
    }

}
```

Detector for PowerPoint document:

``` java
import com.aspose.slides.IOleObjectFrame;
import com.aspose.slides.IShape;
import com.aspose.slides.ISlide;
import com.aspose.slides.Presentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * Implementation of the detector for Microsoft PowerPoint document.
 *
 *
 */
public class PowerPointDocumentDetectorImpl implements DocumentDetector {

    /**
     * LOGGER
     */
    private static final Logger LOG = LoggerFactory.getLogger(PowerPointDocumentDetectorImpl.class);

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("rawtypes")
    @Override
    public boolean isSafe(File f) {
        boolean safeState = false;
        try {
            if ((f != null) && f.exists() && f.canRead()) {
                // Load the file into the PowerPoint document parser
                Presentation presentation = new Presentation(f.getAbsolutePath());
                // First check on PowerPoint format skipped because:
                // FileFormatInfo class is not provided for Aspose Slides API
                // PresentationFactory.getInstance().getPresentationInfo() can be used 
                // but the LoadFormat class miss format like POT or PPT XML
                // Aspose API do not support PPT XML format
                // Get safe state from presence of a VBA project in the presentation
                safeState = (presentation.getVbaProject() == null);
                // If presentation is safe then we pass to OLE objects analysis
                if (safeState) {
                    //Parse all slides of the presentation
                    int totalOLEObjectCount = 0;
                    for (ISlide slide : presentation.getSlides()) {
                        for (IShape shape : slide.getShapes()) {
                            //Check if the current shape is an OLE object
                            if (shape instanceof IOleObjectFrame) {
                                totalOLEObjectCount++;
                            }
                        }
                    }
                    // Update safe status flag according to number of OLE object found
                    if (totalOLEObjectCount != 0) {
                        safeState = false;
                    }
                }

            }
        } catch (Exception e) {
            safeState = false;
            LOG.warn("Error during PowerPoint file analysis !", e);
        }
        return safeState;
    }
}
```

## Case n°2: PDF

Detector for PDF document:

``` java
import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;

/**
 * Implementation of the detector for Adobe PDF document.
 *
 *
 */
public class PdfDocumentDetectorImpl implements DocumentDetector {

    /** LOGGER */
    private static final Logger LOG = LoggerFactory.getLogger(PdfDocumentDetectorImpl.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSafe(File f) {
        boolean safeState = false;
        try {
            if ((f != null) && f.exists()) {
                // Load stream in PDF parser
                // If the stream is not a PDF then exception will be throwed
                // here and safe state will be set to FALSE
                PdfReader reader = new PdfReader(f.getAbsolutePath());
                // Check 1:
                // Detect if the document contains any JavaScript code
                String jsCode = reader.getJavaScript();
                if (jsCode == null) {
                    // OK no JS code then when pass to check 2:
                    // Detect if the document has any embedded files
                    PdfDictionary root = reader.getCatalog();
                    PdfDictionary names = root.getAsDict(PdfName.NAMES);
                    PdfArray namesArray = null;
                    if (names != null) {
                        PdfDictionary embeddedFiles = names.getAsDict(PdfName.EMBEDDEDFILES);
                        namesArray = embeddedFiles.getAsArray(PdfName.NAMES);
                    }
                    // Get safe state from number of embedded files
                    safeState = ((namesArray == null) || namesArray.isEmpty());
                }
            }
        } catch (Exception e) {
            safeState = false;
            LOG.warn("Error during Pdf file analysis !", e);
        }
        return safeState;
    }

}
```

## Case n°3: Images

Sanitizer for Images files:

``` java
import org.apache.commons.imaging.ImageInfo;
import org.apache.commons.imaging.ImageParser;
import org.apache.commons.imaging.Imaging;
import org.apache.commons.imaging.formats.bmp.BmpImageParser;
import org.apache.commons.imaging.formats.gif.GifImageParser;
import org.apache.commons.imaging.formats.pcx.PcxImageParser;
import org.apache.commons.imaging.formats.dcx.DcxImageParser;
import org.apache.commons.imaging.formats.png.PngImageParser;
import org.apache.commons.imaging.formats.tiff.TiffImageParser;
import org.apache.commons.imaging.formats.wbmp.WbmpImageParser;
import org.apache.commons.imaging.formats.xbm.XbmImageParser;
import org.apache.commons.imaging.formats.xpm.XpmImageParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Implementation of the sanitizer for Image file.
 * <p>
 * Use Java built-in API in complement of Apache Commons Imaging 
 * for format not supported by the built-in API.
 *
 * @see "http://commons.apache.org/proper/commons-imaging/"
 * @see "http://commons.apache.org/proper/commons-imaging/formatsupport.html"
 */
public class ImageDocumentSanitizerImpl implements DocumentSanitizer {

    /**
     * LOGGER
     */
    private static final Logger LOG = LoggerFactory.getLogger(ImageDocumentSanitizerImpl.class);


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean madeSafe(File f) {
        boolean safeState = false;
        boolean fallbackOnApacheCommonsImaging;
        try {
            if ((f != null) && f.exists() && f.canRead() && f.canWrite()) {
                //Get the image format
                String formatName;
                try (ImageInputStream iis = ImageIO.createImageInputStream(f)) {
                    Iterator<ImageReader> imageReaderIterator = ImageIO.getImageReaders(iis);
                    //If there not ImageReader instance found so it's means that the current 
                    // format is not supported by the Java built-in API
                    if (!imageReaderIterator.hasNext()) {
                        ImageInfo imageInfo = Imaging.getImageInfo(f);
                        if (imageInfo != null && imageInfo.getFormat() != null 
                        && imageInfo.getFormat().getName() != null) {
                            formatName = imageInfo.getFormat().getName();
                            fallbackOnApacheCommonsImaging = true;
                        } else {
                            throw new IOException("Format of the original image is " + 
                                                "not supported for read operation !");
                        }
                    } else {
                        ImageReader reader = imageReaderIterator.next();
                        formatName = reader.getFormatName();
                        fallbackOnApacheCommonsImaging = false;
                    }
                }

                // Load the image
                BufferedImage originalImage;
                if (!fallbackOnApacheCommonsImaging) {
                    originalImage = ImageIO.read(f);
                } else {
                    originalImage = Imaging.getBufferedImage(f);
                }

                // Check that image has been successfully loaded
                if (originalImage == null) {
                    throw new IOException("Cannot load the original image !");
                }

                // Get current Width and Height of the image
                int originalWidth = originalImage.getWidth(null);
                int originalHeight = originalImage.getHeight(null);


                // Resize the image by removing 1px on Width and Height
                Image resizedImage = originalImage.getScaledInstance(originalWidth - 1, 
                                                                     originalHeight - 1, 
                                                                     Image.SCALE_SMOOTH);

                // Resize the resized image by adding 1px on Width and Height
                // In fact set image to is initial size
                Image initialSizedImage = resizedImage.getScaledInstance(originalWidth, 
                                                                         originalHeight,
                                                                         Image.SCALE_SMOOTH);

                // Save image by overwriting the provided source file content
                BufferedImage sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), 
                                                                 initialSizedImage.getHeight(null), 
                                                                 BufferedImage.TYPE_INT_RGB);
                Graphics bg = sanitizedImage.getGraphics();
                bg.drawImage(initialSizedImage, 0, 0, null);
                bg.dispose();
                try (OutputStream fos = Files.newOutputStream(f.toPath(), StandardOpenOption.WRITE)) {
                    if (!fallbackOnApacheCommonsImaging) {
                        ImageIO.write(sanitizedImage, formatName, fos);
                    } else {
                        ImageParser imageParser;
                        //Handle only formats for which Apache Commons Imaging can successfully write 
                        // (YES in Write column of the reference link) the image format
                        //See reference link in the class header
                        switch (formatName) {
                            case "TIFF": {
                                imageParser = new TiffImageParser();
                                break;
                            }
                            case "PCX": {
                                imageParser = new PcxImageParser();
                                break;
                            }
                            case "DCX": {
                                imageParser = new DcxImageParser();
                                break;
                            }
                            case "BMP": {
                                imageParser = new BmpImageParser();
                                break;
                            }
                            case "GIF": {
                                imageParser = new GifImageParser();
                                break;
                            }
                            case "PNG": {
                                imageParser = new PngImageParser();
                                break;
                            }
                            case "WBMP": {
                                imageParser = new WbmpImageParser();
                                break;
                            }
                            case "XBM": {
                                imageParser = new XbmImageParser();
                                break;
                            }
                            case "XPM": {
                                imageParser = new XpmImageParser();
                                break;
                            }
                            default: {
                                throw new IOException("Format of the original image is not" + 
                                                      " supported for write operation !");
                            }

                        }
                        imageParser.writeImage(sanitizedImage, fos, new HashMap<>());
                    }

                }

                // Set state flag
                safeState = true;
            }
        } catch (Exception e) {
            safeState = false;
            LOG.warn("Error during Image file processing !", e);
        }

        return safeState;
    }
}
```

# Sources of the prototype

GitHub [repository](https://github.com/righettod/document-upload-protection)